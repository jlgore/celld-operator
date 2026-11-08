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

package storageproxy

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

const (
	testBucket = "cells"
	testRegion = "us-east-1"
	testPrefix = "tenants/acme"
)

var realCreds = aws.Credentials{AccessKeyID: "REALKEY", SecretAccessKey: "real-secret", SessionToken: "session"}

// fakeS3 is a tiny S3: it verifies the proxy's SigV4 signature with the
// real credential and implements create-if-absent / compare-and-swap.
type fakeS3 struct {
	t       *testing.T
	mu      sync.Mutex
	objects map[string][]byte
	etags   map[string]string
	seen    []*http.Request
	version int
}

func newFakeS3(t *testing.T) *fakeS3 {
	return &fakeS3{t: t, objects: map[string][]byte{}, etags: map[string]string{}}
}

func (f *fakeS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	clone := r.Clone(context.Background())
	f.seen = append(f.seen, clone)
	if err := verifySignature(r, body); err != nil {
		w.WriteHeader(http.StatusForbidden)
		_, _ = fmt.Fprintf(w, "<Error><Code>SignatureDoesNotMatch</Code><Message>%s</Message></Error>", err)
		return
	}
	key := strings.TrimPrefix(r.URL.Path, "/")
	if !strings.Contains(key, "/") && r.Method == http.MethodGet {
		_, _ = w.Write([]byte(`<?xml version="1.0"?><ListBucketResult><Name>cells</Name><KeyCount>0</KeyCount><IsTruncated>false</IsTruncated></ListBucketResult>`))
		return
	}
	switch r.Method {
	case http.MethodPut:
		current, exists := f.etags[key]
		if r.Header.Get("If-None-Match") == "*" && exists {
			w.WriteHeader(http.StatusPreconditionFailed)
			return
		}
		if match := r.Header.Get("If-Match"); match != "" && match != current {
			w.WriteHeader(http.StatusPreconditionFailed)
			return
		}
		f.version++
		etag := fmt.Sprintf(`"v%d"`, f.version)
		f.objects[key], f.etags[key] = body, etag
		w.Header().Set("ETag", etag)
		w.WriteHeader(http.StatusOK)
	case http.MethodGet, http.MethodHead:
		data, ok := f.objects[key]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Header.Get("If-None-Match") == f.etags[key] {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", f.etags[key])
		w.Header().Set("Content-Length", fmt.Sprint(len(data)))
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodGet {
			_, _ = w.Write(data)
		}
	case http.MethodDelete:
		delete(f.objects, key)
		delete(f.etags, key)
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<?xml version="1.0"?><DeleteResult></DeleteResult>`))
	}
}

// verifySignature recomputes the request's SigV4 signature with the real
// credential, over exactly the headers it claims to have signed.
func verifySignature(r *http.Request, body []byte) error {
	auth := r.Header.Get("Authorization")
	if !strings.Contains(auth, "Credential="+realCreds.AccessKeyID+"/") {
		return fmt.Errorf("not signed with the real credential: %q", auth)
	}
	if r.Header.Get("X-Amz-Security-Token") != realCreds.SessionToken {
		return errors.New("session token missing")
	}
	signed := strings.Split(between(auth, "SignedHeaders=", ","), ";")
	when, err := time.Parse("20060102T150405Z", r.Header.Get("X-Amz-Date"))
	if err != nil {
		return err
	}
	check, _ := http.NewRequest(r.Method, "http://"+r.Host+r.URL.RequestURI(), bytes.NewReader(body))
	check.URL.RawPath = r.URL.RawPath
	for _, name := range signed {
		if name == "host" {
			continue
		}
		check.Header[http.CanonicalHeaderKey(name)] = r.Header.Values(name)
	}
	if r.ContentLength > 0 {
		check.ContentLength = r.ContentLength
	}
	signer := v4.NewSigner(func(o *v4.SignerOptions) { o.DisableURIPathEscaping = true })
	if err := signer.SignHTTP(context.Background(), realCreds, check, r.Header.Get("X-Amz-Content-Sha256"), "s3", testRegion, when); err != nil {
		return err
	}
	if want, got := between(check.Header.Get("Authorization"), "Signature=", ""), between(auth, "Signature=", ""); want != got {
		return fmt.Errorf("signature mismatch")
	}
	return nil
}

func between(s, start, end string) string {
	_, rest, _ := strings.Cut(s, start)
	if end == "" {
		return rest
	}
	value, _, _ := strings.Cut(rest, end)
	return value
}

func newProxy(t *testing.T) (*fakeS3, *s3.Client) {
	t.Helper()
	store := newFakeS3(t)
	upstream := httptest.NewServer(store)
	t.Cleanup(upstream.Close)
	target, _ := url.Parse(upstream.URL)
	handler := NewHandler(Handler{
		Scope:       Scope{Bucket: testBucket, Prefix: testPrefix},
		Upstream:    target,
		Region:      testRegion,
		Credentials: credentials.StaticCredentialsProvider{Value: realCreds},
	})
	proxy := httptest.NewServer(handler)
	t.Cleanup(proxy.Close)
	// The tenant's client: path-style, placeholder key, exactly like celld.
	client := s3.New(s3.Options{
		Region:           testRegion,
		BaseEndpoint:     aws.String(proxy.URL),
		UsePathStyle:     true,
		Credentials:      credentials.NewStaticCredentialsProvider("celld-tenant-acme", "signed-by-proxy", ""),
		RetryMaxAttempts: 1,
	})
	return store, client
}

func statusOf(err error) int {
	var apiErr interface{ HTTPStatusCode() int }
	if errors.As(err, &apiErr) {
		return apiErr.HTTPStatusCode()
	}
	return 0
}

func TestConditionalWritesPassThrough(t *testing.T) {
	store, client := newProxy(t)
	ctx := context.Background()
	key := aws.String("tenants/acme/owners/cell-1")

	first, err := client.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(testBucket), Key: key, Body: strings.NewReader("node-a"), IfNoneMatch: aws.String("*")})
	if err != nil {
		t.Fatalf("create-if-absent: %v", err)
	}
	_, err = client.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(testBucket), Key: key, Body: strings.NewReader("node-b"), IfNoneMatch: aws.String("*")})
	if statusOf(err) != http.StatusPreconditionFailed {
		t.Fatalf("second create-if-absent: got %v, want 412 passed through", err)
	}
	second, err := client.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(testBucket), Key: key, Body: strings.NewReader("node-a-renew"), IfMatch: first.ETag})
	if err != nil {
		t.Fatalf("compare-and-swap with the current etag: %v", err)
	}
	_, err = client.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(testBucket), Key: key, Body: strings.NewReader("stale"), IfMatch: first.ETag})
	if statusOf(err) != http.StatusPreconditionFailed {
		t.Fatalf("stale compare-and-swap: got %v, want 412", err)
	}
	got, err := client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(testBucket), Key: key})
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(got.Body)
	if string(data) != "node-a-renew" || aws.ToString(got.ETag) != aws.ToString(second.ETag) {
		t.Fatalf("read back %q etag %s, want node-a-renew %s", data, aws.ToString(got.ETag), aws.ToString(second.ETag))
	}
	// Exactly one upstream request per client call: nothing was retried.
	if len(store.seen) != 5 {
		t.Fatalf("upstream saw %d requests, want 5 (no replays)", len(store.seen))
	}
	for _, r := range store.seen {
		if strings.Contains(r.Header.Get("Authorization"), "celld-tenant-acme") {
			t.Fatal("caller's placeholder signature reached the store")
		}
	}
	if store.seen[1].Header.Get("If-None-Match") != "*" || store.seen[3].Header.Get("If-Match") != aws.ToString(first.ETag) {
		t.Fatal("conditional headers were not forwarded unchanged")
	}
}

func TestScopeIsEnforcedBeforeUpstream(t *testing.T) {
	store, client := newProxy(t)
	ctx := context.Background()
	denied := map[string]func() error{
		"other tenant key": func() error {
			_, err := client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(testBucket), Key: aws.String("tenants/other/x")})
			return err
		},
		"sibling prefix": func() error {
			_, err := client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(testBucket), Key: aws.String("tenants/acme-evil/x")})
			return err
		},
		"dot-dot escape": func() error {
			_, err := client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(testBucket), Key: aws.String("tenants/acme/../other/x")})
			return err
		},
		"other bucket": func() error {
			_, err := client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String("other"), Key: aws.String("tenants/acme/x")})
			return err
		},
		"list without prefix": func() error {
			_, err := client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: aws.String(testBucket)})
			return err
		},
		"list other prefix": func() error {
			_, err := client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: aws.String(testBucket), Prefix: aws.String("tenants/")})
			return err
		},
		"bulk delete foreign key": func() error {
			_, err := client.DeleteObjects(ctx, &s3.DeleteObjectsInput{Bucket: aws.String(testBucket), Delete: &s3types.Delete{Objects: []s3types.ObjectIdentifier{
				{Key: aws.String("tenants/acme/a")}, {Key: aws.String("tenants/other/b")},
			}}})
			return err
		},
		"copy from foreign key": func() error {
			_, err := client.CopyObject(ctx, &s3.CopyObjectInput{Bucket: aws.String(testBucket), Key: aws.String("tenants/acme/stolen"), CopySource: aws.String("cells/tenants/other/secret")})
			return err
		},
		"acl change": func() error {
			_, err := client.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(testBucket), Key: aws.String("tenants/acme/x"), Body: strings.NewReader("x"), ACL: s3types.ObjectCannedACLPublicRead})
			return err
		},
		"bucket policy": func() error {
			_, err := client.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{Bucket: aws.String(testBucket)})
			return err
		},
		"delete bucket": func() error {
			_, err := client.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: aws.String(testBucket)})
			return err
		},
		"object versions": func() error {
			_, err := client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(testBucket), Key: aws.String("tenants/acme/x"), VersionId: aws.String("1")})
			return err
		},
	}
	for name, call := range denied {
		err := call()
		if statusOf(err) != http.StatusForbidden {
			t.Errorf("%s: got %v, want 403", name, err)
		}
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) && apiErr.ErrorCode() != "AccessDenied" {
			t.Errorf("%s: error code %s, want AccessDenied", name, apiErr.ErrorCode())
		}
	}
	if len(store.seen) != 0 {
		t.Fatalf("denied requests reached the store: %d", len(store.seen))
	}
}

func TestAllowedBucketOperations(t *testing.T) {
	store, client := newProxy(t)
	ctx := context.Background()
	if _, err := client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: aws.String(testBucket), Prefix: aws.String("tenants/acme/cells/"), Delimiter: aws.String("/"), StartAfter: aws.String("tenants/acme/cells/a")}); err != nil {
		t.Fatalf("list in prefix: %v", err)
	}
	if _, err := client.DeleteObjects(ctx, &s3.DeleteObjectsInput{Bucket: aws.String(testBucket), Delete: &s3types.Delete{Objects: []s3types.ObjectIdentifier{{Key: aws.String("tenants/acme/a")}, {Key: aws.String("tenants/acme/b")}}}}); err != nil {
		t.Fatalf("bulk delete in prefix: %v", err)
	}
	if _, err := client.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(testBucket), Key: aws.String("tenants/acme/src"), Body: strings.NewReader("x")}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.CopyObject(ctx, &s3.CopyObjectInput{Bucket: aws.String(testBucket), Key: aws.String("tenants/acme/dst"), CopySource: aws.String("cells/tenants/acme/src")}); err != nil {
		t.Fatalf("copy in prefix: %v", err)
	}
	if len(store.seen) != 4 {
		t.Fatalf("upstream saw %d requests, want 4", len(store.seen))
	}
}

// TestRawObjectStoreShapes covers request shapes the AWS SDK does not
// produce but celld's object_store client does: a percent-encoded key
// forwarded byte-for-byte, an unsigned payload, and a streaming payload.
func TestRawObjectStoreShapes(t *testing.T) {
	store := newFakeS3(t)
	upstream := httptest.NewServer(store)
	defer upstream.Close()
	target, _ := url.Parse(upstream.URL)
	handler := NewHandler(Handler{Scope: Scope{Bucket: testBucket, Prefix: testPrefix}, Upstream: target, Region: testRegion, Credentials: credentials.StaticCredentialsProvider{Value: realCreds}})

	body := []byte("frame")
	sum := md5.Sum(body)
	req := httptest.NewRequest(http.MethodPut, "/cells/tenants/acme/cell%3A1/frame%201", bytes.NewReader(body))
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=celld-tenant-acme/x")
	req.Header.Set("X-Amz-Content-Sha256", unsignedPayload)
	req.Header.Set("Content-MD5", base64.StdEncoding.EncodeToString(sum[:]))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Header().Get("ETag") == "" {
		t.Fatalf("unsigned PUT: %d %s", rec.Code, rec.Body)
	}
	if got := store.seen[0].URL.EscapedPath(); got != "/cells/tenants/acme/cell%3A1/frame%201" {
		t.Fatalf("forwarded path %q, want the caller's escaping", got)
	}
	if store.seen[0].Header.Get("Content-MD5") == "" {
		t.Fatal("Content-MD5 dropped")
	}

	req = httptest.NewRequest(http.MethodPut, "/cells/tenants/acme/x", strings.NewReader("x"))
	req.Header.Set("X-Amz-Content-Sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotImplemented || len(store.seen) != 1 {
		t.Fatalf("streaming payload: %d, upstream requests %d", rec.Code, len(store.seen))
	}
}

func TestParseScope(t *testing.T) {
	for spec, ok := range map[string]bool{
		"s3://cells/tenants/acme":  true,
		"s3://cells/tenants/acme/": true,
		"s3://cells":               false,
		"s3://cells/":              false,
		"gs://cells/tenants/acme":  false,
		"s3://cells/tenants/../x":  false,
		"s3://cells/tenants//acme": false,
	} {
		if _, err := ParseScope(spec); (err == nil) != ok {
			t.Errorf("ParseScope(%q) err=%v, want ok=%v", spec, err, ok)
		}
	}
}

func TestSessionPolicyScopesToPrefix(t *testing.T) {
	policy := SessionPolicy(Scope{Bucket: testBucket, Prefix: testPrefix})
	for _, want := range []string{`"arn:aws:s3:::cells/tenants/acme/*"`, `"s3:prefix":["tenants/acme","tenants/acme/*"]`} {
		if !strings.Contains(policy, want) {
			t.Errorf("session policy %s lacks %s", policy, want)
		}
	}
	if strings.Contains(policy, `"*"`) {
		t.Errorf("session policy grants a wildcard resource: %s", policy)
	}
}
