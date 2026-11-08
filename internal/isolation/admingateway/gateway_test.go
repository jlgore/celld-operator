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

package admingateway

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	authenticationv1 "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

const adminToken = "admin-token"

type staticReviewer map[string]string

func (s staticReviewer) Review(_ context.Context, token string) (string, error) {
	if user, ok := s[token]; ok {
		return user, nil
	}
	return "", ErrUnauthenticated
}

func TestGatewayAuthorizesAndStripsToken(t *testing.T) {
	var gotAuth, gotPath string
	runtimeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotPath = r.Header.Get("Authorization"), r.URL.Path
		_, _ = w.Write([]byte(`{"occupied":1}`))
	}))
	defer runtimeServer.Close()
	host, port, _ := net.SplitHostPort(runtimeServer.Listener.Addr().String())
	portNumber, _ := strconv.Atoi(port)
	gateway := &Gateway{
		Reviewer:        staticReviewer{adminToken: "system:serviceaccount:ops:admin", "other-token": "system:serviceaccount:tenant-b:celld"},
		Allowed:         map[string]bool{"system:serviceaccount:ops:admin": true},
		Fleet:           "acme-celld",
		HeadlessService: host,
		Port:            portNumber,
	}
	cases := []struct {
		name, token, node string
		want              int
	}{
		{"no token", "", "", http.StatusUnauthorized},
		{"bad token", "forged", "", http.StatusUnauthorized},
		{"other tenant's identity", "other-token", "", http.StatusForbidden},
		{"allowed", adminToken, "", http.StatusOK},
		{"node outside the fleet", adminToken, "other-celld-0", http.StatusBadRequest},
		{"host injection", adminToken, "acme-celld-0.evil.com", http.StatusBadRequest},
	}
	for _, c := range cases {
		req := httptest.NewRequest(http.MethodGet, "/state", nil)
		if c.token != "" {
			req.Header.Set("Authorization", "Bearer "+c.token)
		}
		if c.node != "" {
			req.Header.Set(NodeHeader, c.node)
		}
		rec := httptest.NewRecorder()
		gateway.ServeHTTP(rec, req)
		if rec.Code != c.want {
			t.Errorf("%s: status %d, want %d", c.name, rec.Code, c.want)
		}
	}
	if gotPath != "/state" || gotAuth != "" {
		t.Fatalf("runtime saw path %q auth %q; the bearer token must not be forwarded", gotPath, gotAuth)
	}
}

func TestTokenReviewerRequiresAudience(t *testing.T) {
	client := fake.NewClientset()
	client.PrependReactor("create", "tokenreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
		review := action.(k8stesting.CreateAction).GetObject().(*authenticationv1.TokenReview)
		review.Status = authenticationv1.TokenReviewStatus{Authenticated: true, User: authenticationv1.UserInfo{Username: "u"}}
		if review.Spec.Token == "right-audience" {
			review.Status.Audiences = review.Spec.Audiences
		}
		return true, review, nil
	})
	reviewer := TokenReviewer{Client: client, Audience: "celld-admin.tenant-acme"}
	if user, err := reviewer.Review(context.Background(), "right-audience"); err != nil || user != "u" {
		t.Fatalf("Review = %q, %v", user, err)
	}
	if _, err := reviewer.Review(context.Background(), "default-audience"); err != ErrUnauthenticated {
		t.Fatalf("a token without the gateway audience must be refused, got %v", err)
	}
}
