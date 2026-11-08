//go:build e2e

// The isolation fixture stands in for celld in the tenant isolation e2e
// suite. It serves what the operator needs from a celld node (health on
// :8080, /state on :8081) and adds probe endpoints that run checks from
// inside the workload process: under a microVM runtime they execute in
// the guest, which `kubectl exec` (host side) cannot reach.
//
//	GET /__isolation/dial?addr=host:port       TCP reachability
//	GET /__isolation/s3?method=GET&key=...      S3 through the configured endpoint
//	GET /__isolation/creds?secret=...           credential exposure report
//
// On SIGTERM or SIGINT it records which signal arrived on its volume, so
// the next boot can report whether the previous stop was graceful.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func main() {
	watch := os.Getenv("CELLD_WATCH")
	marker := filepath.Join(watch, "last-stop")
	if previous, err := os.ReadFile(marker); err == nil {
		log.Printf("Previous stop: %s", strings.TrimSpace(string(previous)))
		_ = os.Remove(marker)
	} else {
		log.Printf("Previous stop: none recorded")
	}
	log.Printf("Boot kernel=%s", kernel())

	public := http.NewServeMux()
	public.HandleFunc("/.well-known/celld/health", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	public.HandleFunc("/__isolation/dial", dial)
	public.HandleFunc("/__isolation/s3", s3Probe)
	public.HandleFunc("/__isolation/creds", creds)
	public.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	internal := http.NewServeMux()
	internal.HandleFunc("/state", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"occupied":1,"restoring":0,"shedding":null,"deployment":{"version":"deploy-a","generation":1,"draining":[],"swapping":0}}`))
	})
	servers := []*http.Server{
		{Addr: ":8080", Handler: public, ReadHeaderTimeout: time.Second},
		{Addr: ":8081", Handler: internal, ReadHeaderTimeout: time.Second},
	}
	for _, s := range servers {
		go func() { _ = s.ListenAndServe() }()
	}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	sig := <-signals
	record := fmt.Sprintf("signal=%s graceful=true at=%d", sig, time.Now().UnixMilli())
	if err := os.WriteFile(marker, []byte(record), 0o600); err != nil {
		log.Printf("Could not record stop: %v", err)
	}
	log.Printf("Stopping on %s", sig)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, s := range servers {
		_ = s.Shutdown(ctx)
	}
}

func kernel() string {
	raw, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(raw))
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func dial(w http.ResponseWriter, r *http.Request) {
	conn, err := net.DialTimeout("tcp", r.URL.Query().Get("addr"), 3*time.Second)
	if err != nil {
		writeJSON(w, map[string]any{"connected": false, "error": err.Error()})
		return
	}
	_ = conn.Close()
	writeJSON(w, map[string]any{"connected": true})
}

// s3Probe uses exactly the credential and endpoint celld would get.
func s3Probe(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	client := s3.New(s3.Options{
		Region:           envOr("AWS_REGION", "us-east-1"),
		BaseEndpoint:     aws.String(os.Getenv("S3_ENDPOINT")),
		UsePathStyle:     true,
		RetryMaxAttempts: 1,
		Credentials:      credentials.NewStaticCredentialsProvider(os.Getenv("AWS_ACCESS_KEY_ID"), os.Getenv("AWS_SECRET_ACCESS_KEY"), ""),
	})
	bucket, _, _ := strings.Cut(strings.TrimPrefix(os.Getenv("CELLD_BUCKET"), "s3://"), "/")
	if b := query.Get("bucket"); b != "" {
		bucket = b
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	var err error
	switch query.Get("method") {
	case "PUT":
		_, err = client.PutObject(ctx, &s3.PutObjectInput{Bucket: &bucket, Key: aws.String(query.Get("key")), Body: strings.NewReader("probe"), IfNoneMatch: optional(query.Get("ifNoneMatch"))})
	case "LIST":
		_, err = client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: &bucket, Prefix: aws.String(query.Get("prefix"))})
	default:
		var out *s3.GetObjectOutput
		out, err = client.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: aws.String(query.Get("key"))})
		if err == nil {
			_, _ = io.Copy(io.Discard, out.Body)
		}
	}
	status := 200
	var httpErr interface{ HTTPStatusCode() int }
	if errors.As(err, &httpErr) {
		status = httpErr.HTTPStatusCode()
	} else if err != nil {
		status = 0
	}
	result := map[string]any{"status": status}
	if err != nil {
		result["error"] = err.Error()
	}
	writeJSON(w, result)
}

func optional(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// creds reports every place a bucket credential could hide: environment,
// files (including Kubernetes token mounts), and cloud metadata services.
// secret, when given, is a real credential value that must appear nowhere.
func creds(w http.ResponseWriter, r *http.Request) {
	secret := r.URL.Query().Get("secret")
	env := map[string]string{}
	var leakedEnv []string
	for _, kv := range os.Environ() {
		key, value, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(key, "AWS_") || strings.HasPrefix(key, "AZURE_") || strings.HasPrefix(key, "GOOGLE_") || strings.Contains(key, "TOKEN") {
			env[key] = value
		}
		if secret != "" && strings.Contains(value, secret) {
			leakedEnv = append(leakedEnv, key)
		}
	}
	var leakedFiles, tokenFiles []string
	for _, root := range []string{"/var/run/secrets", "/run/secrets", "/etc", "/tmp", "/var/lib/celld", "/root", "/home"} {
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			if strings.HasSuffix(path, "/token") || strings.Contains(path, "serviceaccount") {
				tokenFiles = append(tokenFiles, path)
			}
			info, err := d.Info()
			if err != nil || info.Size() > 1<<20 {
				return nil
			}
			data, err := os.ReadFile(path)
			if err == nil && secret != "" && strings.Contains(string(data), secret) {
				leakedFiles = append(leakedFiles, path)
			}
			return nil
		})
	}
	metadata := map[string]bool{}
	for name, addr := range map[string]string{
		"aws-imds": "169.254.169.254:80", "ecs-task": "169.254.170.2:80", "eks-pod-identity": "169.254.170.23:80",
		"gce": "metadata.google.internal:80", "azure-imds": "169.254.169.254:80",
	} {
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		metadata[name] = err == nil
		if err == nil {
			_ = conn.Close()
		}
	}
	writeJSON(w, map[string]any{
		"env": env, "leakedEnv": leakedEnv, "leakedFiles": leakedFiles,
		"tokenFiles": tokenFiles, "metadataReachable": metadata, "kernel": kernel(),
	})
}
