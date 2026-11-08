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
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

const (
	unsignedPayload = "UNSIGNED-PAYLOAD"
	// maxDeleteBody bounds a buffered DeleteObjects body (1000 keys of
	// up to 1 KiB each, plus XML overhead).
	maxDeleteBody = 2 << 20
)

var hexDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Request headers never forwarded: hop-by-hop headers, the caller's
// signature (replaced), and proxy hints.
var droppedRequestHeaders = map[string]bool{
	"Authorization": true, "X-Amz-Date": true, "X-Amz-Security-Token": true,
	"X-Amz-Content-Sha256": true, "Host": true, "Connection": true, "Keep-Alive": true,
	"Proxy-Authorization": true, "Proxy-Connection": true, "Te": true, "Trailer": true,
	"Transfer-Encoding": true, "Upgrade": true, "Expect": true,
	"X-Forwarded-For": true, "X-Forwarded-Host": true, "X-Forwarded-Proto": true, "Forwarded": true,
}

var droppedResponseHeaders = map[string]bool{
	"Connection": true, "Keep-Alive": true, "Proxy-Authenticate": true, "Te": true,
	"Trailer": true, "Transfer-Encoding": true, "Upgrade": true,
}

// Handler is the signing proxy.
type Handler struct {
	Scope Scope
	// Upstream is the store endpoint, e.g. https://s3.us-east-1.amazonaws.com.
	Upstream *url.URL
	// VirtualHosted addresses the bucket as a host label (AWS without a
	// custom endpoint); otherwise path-style.
	VirtualHosted bool
	Region        string
	Credentials   aws.CredentialsProvider
	Client        *http.Client
	Log           *slog.Logger

	signer *v4.Signer
}

// NewHandler fills defaults. The client never retries: a conditional PUT
// repeated by a transport can answer 412 for a write that committed, which
// celld would misread as a lost ownership race (FINDINGS.md, section 2).
func NewHandler(h Handler) *Handler {
	if h.Client == nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.MaxIdleConnsPerHost = 64
		h.Client = &http.Client{
			Transport: transport,
			// Redirects would re-send a signed request somewhere else.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	if h.Log == nil {
		h.Log = slog.Default()
	}
	h.signer = v4.NewSigner(func(o *v4.SignerOptions) {
		// S3 signs the path as sent, without a second escaping pass.
		o.DisableURIPathEscaping = true
	})
	return &h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	status, err := h.serve(w, r)
	if err != nil {
		h.Log.Warn("Refused storage request", "method", r.Method, "path", r.URL.Path, "status", status, "error", err.Error())
		writeError(w, status, err)
		return
	}
	h.Log.Debug("Proxied storage request", "method", r.Method, "path", r.URL.Path, "status", status, "duration", time.Since(start))
}

func (h *Handler) serve(w http.ResponseWriter, r *http.Request) (int, error) {
	if strings.HasPrefix(r.Header.Get("X-Amz-Content-Sha256"), "STREAMING-") {
		// Chunk signatures would have to be recomputed per chunk.
		return http.StatusNotImplemented, errors.New("streaming payload signing is not supported by the tenant storage proxy")
	}

	var deleteBody []byte
	body := r.Body
	if r.Method == http.MethodPost && r.URL.Query().Has("delete") {
		buffered, err := io.ReadAll(io.LimitReader(r.Body, maxDeleteBody+1))
		if err != nil || len(buffered) > maxDeleteBody {
			return http.StatusBadRequest, errors.New("DeleteObjects body unreadable or too large")
		}
		deleteBody = buffered
		body = io.NopCloser(bytes.NewReader(buffered))
	}
	req, err := h.Scope.authorize(r, deleteBody)
	if err != nil {
		return http.StatusForbidden, err
	}

	out, err := h.upstreamRequest(r.Context(), r, req, body)
	if err != nil {
		return http.StatusBadGateway, err
	}
	payloadHash := r.Header.Get("X-Amz-Content-Sha256")
	switch {
	case deleteBody != nil:
		sum := sha256.Sum256(deleteBody)
		payloadHash = hex.EncodeToString(sum[:])
	case hexDigest.MatchString(payloadHash):
		// The store verifies the body against this digest, so reusing the
		// caller's value needs no trust in the caller.
	default:
		payloadHash = unsignedPayload
	}
	out.Header.Set("X-Amz-Content-Sha256", payloadHash)

	creds, err := h.Credentials.Retrieve(r.Context())
	if err != nil {
		return http.StatusServiceUnavailable, fmt.Errorf("storage credential unavailable: %w", err)
	}
	if err := h.signer.SignHTTP(r.Context(), creds, out, payloadHash, "s3", h.Region, time.Now().UTC()); err != nil {
		return http.StatusInternalServerError, fmt.Errorf("sign request: %w", err)
	}

	resp, err := h.Client.Do(out)
	if err != nil {
		return http.StatusBadGateway, fmt.Errorf("upstream: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	// Status, ETag, and every other header pass through unchanged: the
	// caller's fencing logic reads 200/304/404/409/412 and the ETag.
	for name, values := range resp.Header {
		if droppedResponseHeaders[http.CanonicalHeaderKey(name)] {
			continue
		}
		w.Header()[name] = values
	}
	w.WriteHeader(resp.StatusCode)
	if r.Method != http.MethodHead {
		_, _ = io.Copy(w, resp.Body)
	}
	return resp.StatusCode, nil
}

func (h *Handler) upstreamRequest(ctx context.Context, in *http.Request, req request, body io.ReadCloser) (*http.Request, error) {
	target := *h.Upstream
	target.RawQuery = in.URL.RawQuery
	escapedPath := "/" + url.PathEscape(h.Scope.Bucket)
	if req.escapedKey != "" {
		escapedPath += "/" + req.escapedKey
	}
	if h.VirtualHosted {
		target.Host = h.Scope.Bucket + "." + h.Upstream.Host
		escapedPath = "/" + req.escapedKey
	}
	basePath := strings.TrimSuffix(h.Upstream.EscapedPath(), "/")
	escapedPath = basePath + escapedPath
	decoded, err := url.PathUnescape(escapedPath)
	if err != nil {
		return nil, err
	}
	target.Path, target.RawPath = decoded, escapedPath

	out, err := http.NewRequestWithContext(ctx, in.Method, target.String(), nil)
	if err != nil {
		return nil, err
	}
	// NewRequest re-parses the URL; pin the exact escaping celld used.
	out.URL.Path, out.URL.RawPath = decoded, escapedPath
	if body != nil && body != http.NoBody && in.ContentLength != 0 {
		out.Body = body
		out.ContentLength = in.ContentLength
	}
	// No GetBody: the transport must never replay a request body.
	out.GetBody = nil
	for name, values := range in.Header {
		canonical := http.CanonicalHeaderKey(name)
		if droppedRequestHeaders[canonical] {
			continue
		}
		out.Header[canonical] = append([]string(nil), values...)
	}
	return out, nil
}

// writeError answers in S3's XML error shape so SDK clients surface it.
func writeError(w http.ResponseWriter, status int, err error) {
	code := "AccessDenied"
	switch status {
	case http.StatusBadRequest:
		code = "InvalidRequest"
	case http.StatusNotImplemented:
		code = "NotImplemented"
	case http.StatusServiceUnavailable, http.StatusBadGateway, http.StatusInternalServerError:
		code = "ServiceUnavailable"
	}
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	var message bytes.Buffer
	_ = xml.EscapeText(&message, []byte(err.Error()))
	_, _ = fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?><Error><Code>%s</Code><Message>%s</Message></Error>`, code, message.String())
}
