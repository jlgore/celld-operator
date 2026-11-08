/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// isolation-proxy runs the per-tenant data-plane helpers the Tenant
// controller deploys next to a fleet:
//
//	isolation-proxy storage ...  the prefix-enforcing S3 signing proxy
//	isolation-proxy admin ...    the authenticating admin-API gateway
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/ezgamehost/celld-operator/internal/isolation/admingateway"
	"github.com/ezgamehost/celld-operator/internal/isolation/storageproxy"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	slog.SetDefault(logger)
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: isolation-proxy storage|admin [flags]")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "storage":
		err = runStorage(os.Args[2:])
	case "admin":
		err = runAdmin(os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		logger.Error("Exited with error", "error", err.Error())
		os.Exit(1)
	}
}

func runStorage(args []string) error {
	fs := flag.NewFlagSet("storage", flag.ExitOnError)
	listen := fs.String("listen", ":9000", "S3 listener for the tenant fleet")
	healthListen := fs.String("health-listen", ":9001", "Health listener")
	bucket := fs.String("bucket", "", "Tenant scope, s3://bucket/prefix")
	endpoint := fs.String("endpoint", "", "Upstream S3 endpoint; empty means AWS S3 in --region")
	region := fs.String("region", "us-east-1", "Signing region")
	source := fs.String("credential-source", "webIdentity", "Credential source: webIdentity or static")
	credentialsDir := fs.String("credentials-dir", "",
		"static: directory with AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY files")
	roleARN := fs.String("role-arn", "", "webIdentity: role to assume")
	tokenFile := fs.String("token-file", "/var/run/secrets/tokens/sts/token",
		"webIdentity: projected ServiceAccount token")
	stsEndpoint := fs.String("sts-endpoint", "", "webIdentity: STS endpoint override")
	sessionDuration := fs.Duration("session-duration", time.Hour, "webIdentity: credential lifetime")
	sessionName := fs.String("session-name", "celld-tenant-proxy", "webIdentity: role session name")
	scopePolicy := fs.Bool("scope-session-policy", true, "webIdentity: attach a prefix-scoped session policy")
	if err := fs.Parse(args); err != nil {
		return err
	}
	scope, err := storageproxy.ParseScope(*bucket)
	if err != nil {
		return err
	}
	virtualHosted := *endpoint == ""
	upstreamURL := *endpoint
	if virtualHosted {
		upstreamURL = fmt.Sprintf("https://s3.%s.amazonaws.com", *region)
	}
	upstream, err := url.Parse(upstreamURL)
	if err != nil || (upstream.Scheme != "https" && upstream.Scheme != "http") || upstream.Host == "" {
		return fmt.Errorf("invalid --endpoint %q", *endpoint)
	}
	creds, err := storageproxy.NewCredentials(*source, storageproxy.CredentialConfig{
		Scope: scope, Region: *region, Dir: *credentialsDir,
		RoleARN: *roleARN, TokenFile: *tokenFile, STSEndpoint: *stsEndpoint,
		SessionDuration: *sessionDuration, SessionName: *sessionName, ScopeSessionPolicy: *scopePolicy,
	})
	if err != nil {
		return err
	}
	handler := storageproxy.NewHandler(storageproxy.Handler{
		Scope: scope, Upstream: upstream, VirtualHosted: virtualHosted, Region: *region, Credentials: creds,
	})
	health := http.NewServeMux()
	health.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	health.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		// Ready only with a usable credential, so a broken trust policy
		// shows up as an unready proxy instead of fleet self-fences.
		if _, err := creds.Retrieve(r.Context()); err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	slog.Info("Starting storage proxy",
		"bucket", scope.Bucket, "prefix", scope.Prefix, "upstream", upstream.String(), "source", *source)
	return serve(map[string]http.Handler{*listen: handler, *healthListen: health})
}

func runAdmin(args []string) error {
	fs := flag.NewFlagSet("admin", flag.ExitOnError)
	listen := fs.String("listen", ":8090", "Gateway listener")
	healthListen := fs.String("health-listen", ":8091", "Health listener")
	fleet := fs.String("fleet", "", "Fleet StatefulSet name")
	headless := fs.String("headless-service", "", "Headless Service FQDN of the fleet")
	port := fs.Int("port", 8081, "Runtime admin port")
	audience := fs.String("audience", "", "Token audience the gateway accepts")
	allowed := fs.String("allowed", "", "Comma-separated allowed Kubernetes usernames")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *fleet == "" || *headless == "" || *audience == "" {
		return errors.New("--fleet, --headless-service and --audience are required")
	}
	config, err := rest.InClusterConfig()
	if err != nil {
		return err
	}
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return err
	}
	allow := map[string]bool{}
	for user := range strings.SplitSeq(*allowed, ",") {
		if user = strings.TrimSpace(user); user != "" {
			allow[user] = true
		}
	}
	gateway := &admingateway.Gateway{
		Reviewer: admingateway.TokenReviewer{Client: client, Audience: *audience},
		Allowed:  allow, Fleet: *fleet, HeadlessService: *headless, Port: *port,
	}
	health := http.NewServeMux()
	health.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	slog.Info("Starting admin gateway", "fleet", *fleet, "allowed", len(allow))
	return serve(map[string]http.Handler{*listen: gateway, *healthListen: health})
}

// serve runs each listener until SIGTERM, then drains in-flight requests.
func serve(listeners map[string]http.Handler) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	errs := make(chan error, len(listeners))
	servers := make([]*http.Server, 0, len(listeners))
	for addr, handler := range listeners {
		server := &http.Server{Addr: addr, Handler: handler, ReadHeaderTimeout: 10 * time.Second}
		servers = append(servers, server)
		go func() {
			if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errs <- err
			}
		}()
	}
	select {
	case err := <-errs:
		return err
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for _, server := range servers {
		_ = server.Shutdown(shutdown)
	}
	return nil
}
