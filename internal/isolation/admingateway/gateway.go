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

// Package admingateway authenticates access to a tenant runtime's admin
// listener. celld's operator API on :8081 is unauthenticated upstream and
// also runs application code (/cell/, /do/); the gateway is the only
// tenant-facing way in. Callers present a Kubernetes bearer token minted
// for the gateway's audience; the gateway verifies it with a TokenReview,
// checks the Tenant's allowlist, and forwards to one node's admin port.
package admingateway

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// NodeHeader selects which fleet node to reach, e.g. "acme-celld-1".
// Unset reaches any node through the headless Service.
const NodeHeader = "X-Celld-Node"

// Reviewer authenticates a bearer token for an audience and returns the
// Kubernetes username it belongs to.
type Reviewer interface {
	Review(ctx context.Context, token string) (username string, err error)
}

// ErrUnauthenticated is returned by a Reviewer for an invalid token.
var ErrUnauthenticated = errors.New("token not authenticated")

// Gateway is the authenticating reverse proxy.
type Gateway struct {
	Reviewer Reviewer
	// Allowed are Kubernetes usernames, e.g.
	// "system:serviceaccount:platform-ops:celld-admin".
	Allowed map[string]bool
	// Fleet is the StatefulSet name; node names must be Fleet-<ordinal>.
	Fleet string
	// HeadlessService is "<svc>.<namespace>.svc.<domain>".
	HeadlessService string
	Port            int
	Log             *slog.Logger

	cacheMu sync.Mutex
	cache   map[[32]byte]cached
}

type cached struct {
	username string
	expires  time.Time
}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || token == "" {
		g.reject(w, r, http.StatusUnauthorized, "", "missing bearer token")
		return
	}
	username, err := g.authenticate(r.Context(), token)
	if err != nil {
		status := http.StatusUnauthorized
		if !errors.Is(err, ErrUnauthenticated) {
			status = http.StatusServiceUnavailable
		}
		g.reject(w, r, status, "", err.Error())
		return
	}
	if !g.Allowed[username] {
		g.reject(w, r, http.StatusForbidden, username, "principal is not allowed for this tenant")
		return
	}
	host := g.HeadlessService
	if node := r.Header.Get(NodeHeader); node != "" {
		if !regexp.MustCompile(`^` + regexp.QuoteMeta(g.Fleet) + `-[0-9]{1,3}$`).MatchString(node) {
			g.reject(w, r, http.StatusBadRequest, username, "unknown node")
			return
		}
		host = node + "." + g.HeadlessService
	}
	target := &url.URL{Scheme: "http", Host: fmt.Sprintf("%s:%d", host, g.Port)}
	g.log().Info("Forwarded admin request", "user", username, "method", r.Method, "path", r.URL.Path, "node", r.Header.Get(NodeHeader))
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			// The token is for the gateway only; never hand it to the runtime.
			pr.Out.Header.Del("Authorization")
			pr.Out.Header.Del(NodeHeader)
		},
	}
	proxy.ServeHTTP(w, r)
}

func (g *Gateway) authenticate(ctx context.Context, token string) (string, error) {
	key := sha256.Sum256([]byte(token))
	g.cacheMu.Lock()
	if hit, ok := g.cache[key]; ok && time.Now().Before(hit.expires) {
		g.cacheMu.Unlock()
		return hit.username, nil
	}
	g.cacheMu.Unlock()
	username, err := g.Reviewer.Review(ctx, token)
	if err != nil {
		return "", err
	}
	g.cacheMu.Lock()
	if g.cache == nil {
		g.cache = map[[32]byte]cached{}
	}
	// Short TTL bounds how long a revoked token keeps working.
	g.cache[key] = cached{username: username, expires: time.Now().Add(30 * time.Second)}
	g.cacheMu.Unlock()
	return username, nil
}

func (g *Gateway) reject(w http.ResponseWriter, r *http.Request, status int, user, reason string) {
	g.log().Warn("Refused admin request", "user", user, "method", r.Method, "path", r.URL.Path, "status", status, "reason", reason)
	http.Error(w, reason, status)
}

func (g *Gateway) log() *slog.Logger {
	if g.Log == nil {
		return slog.Default()
	}
	return g.Log
}
