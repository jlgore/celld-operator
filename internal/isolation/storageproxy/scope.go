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

// Package storageproxy is the per-tenant S3 signing proxy. The runtime in
// the microVM holds only a placeholder key; it sends path-style requests
// here, and the proxy (1) confines every key-bearing input to the tenant's
// bucket and prefix, (2) strips the caller's signature, and (3) re-signs
// with a short-lived credential the VM never sees. Conditional-write
// headers and status codes pass through unchanged because celld fences
// Durable Object ownership with them (docs/isolation/FINDINGS.md, section 2).
package storageproxy

import (
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// Scope is the slice of the store a tenant may touch.
type Scope struct {
	Bucket string
	// Prefix has no leading or trailing slash, e.g. "tenants/acme".
	Prefix string
}

// ParseScope reads "s3://bucket/prefix".
func ParseScope(spec string) (Scope, error) {
	rest, ok := strings.CutPrefix(spec, "s3://")
	if !ok {
		return Scope{}, fmt.Errorf("bucket %q: only s3:// is supported", spec)
	}
	bucket, prefix, _ := strings.Cut(rest, "/")
	prefix = strings.Trim(prefix, "/")
	if bucket == "" || prefix == "" {
		return Scope{}, fmt.Errorf("bucket %q: a bucket and a non-empty prefix are required", spec)
	}
	if !safeKey(prefix) {
		return Scope{}, fmt.Errorf("bucket %q: prefix must not contain empty, '.' or '..' segments", spec)
	}
	return Scope{Bucket: bucket, Prefix: prefix}, nil
}

// errDenied marks a request outside the tenant's scope (403).
var errDenied = errors.New("access denied by tenant storage proxy")

func deny(format string, args ...any) error {
	return fmt.Errorf("%w: %s", errDenied, fmt.Sprintf(format, args...))
}

// contains reports whether key lies inside the scope prefix.
func (s Scope) contains(key string) bool {
	return safeKey(key) && (key == s.Prefix || strings.HasPrefix(key, s.Prefix+"/"))
}

// containsListPrefix reports whether a ListObjects prefix stays inside the
// scope. "tenants/acme" (no slash) would also match "tenants/acme-evil",
// so only the exact prefix or prefix/... is accepted.
func (s Scope) containsListPrefix(prefix string) bool {
	return prefix == s.Prefix || prefix == s.Prefix+"/" || s.contains(prefix)
}

// safeKey rejects keys some stores normalize ("a/../b") before resolving,
// which would turn a prefix check on the literal key into a bypass.
func safeKey(key string) bool {
	if key == "" || strings.HasPrefix(key, "/") {
		return false
	}
	for i, segment := range strings.Split(key, "/") {
		if segment == "." || segment == ".." {
			return false
		}
		// An empty segment is only tolerated as a trailing slash.
		if segment == "" && i != strings.Count(key, "/") {
			return false
		}
	}
	return !strings.ContainsAny(key, "\x00\\")
}

// Query parameters the proxy forwards. Anything else (acl, policy,
// versionId, tagging, lifecycle, ...) is refused: celld never sends it, and
// several of them reach outside the prefix or change bucket configuration.
var (
	listParams = map[string]bool{
		"list-type": true, "prefix": true, "delimiter": true, "start-after": true,
		"continuation-token": true, "max-keys": true, "encoding-type": true,
		"fetch-owner": true, "marker": true, "x-id": true,
	}
	objectParams = map[string]bool{"uploads": true, "uploadId": true, "partNumber": true, "x-id": true}
)

// Headers that grant access or lock objects; refused outright.
var forbiddenHeaderPrefixes = []string{
	"x-amz-acl", "x-amz-grant-", "x-amz-object-lock-", "x-amz-bypass-governance-retention",
	"x-amz-website-redirect-location", "x-amz-request-payer",
}

// request is a parsed path-style S3 request.
type request struct {
	key string // empty for bucket-level requests
	// escapedKey is the key exactly as the caller encoded it, so the
	// forwarded path matches what celld signed for.
	escapedKey string
}

// authorize checks one request against the scope. deleteBody is the
// buffered body of a DeleteObjects call (nil otherwise).
func (s Scope) authorize(r *http.Request, deleteBody []byte) (request, error) {
	bucket, key, escapedKey, err := splitPath(r.URL)
	if err != nil {
		return request{}, deny("%v", err)
	}
	if bucket != s.Bucket {
		return request{}, deny("bucket %q is not the tenant bucket", bucket)
	}
	for name := range r.Header {
		lower := strings.ToLower(name)
		for _, forbidden := range forbiddenHeaderPrefixes {
			if strings.HasPrefix(lower, forbidden) {
				return request{}, deny("header %s is not allowed", name)
			}
		}
	}
	if source := r.Header.Get("x-amz-copy-source"); source != "" {
		if err := s.authorizeCopySource(source); err != nil {
			return request{}, err
		}
	}
	query := r.URL.Query()
	if key == "" {
		return request{}, s.authorizeBucketRequest(r.Method, query, deleteBody)
	}
	if !s.contains(key) {
		return request{}, deny("key %q is outside prefix %q", key, s.Prefix)
	}
	for name := range query {
		if !objectParams[name] {
			return request{}, deny("query parameter %q is not allowed on objects", name)
		}
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodPut, http.MethodDelete, http.MethodPost:
	default:
		return request{}, deny("method %s is not allowed", r.Method)
	}
	return request{key: key, escapedKey: escapedKey}, nil
}

func (s Scope) authorizeBucketRequest(method string, query url.Values, deleteBody []byte) error {
	switch {
	case method == http.MethodPost && query.Has("delete"):
		if len(query) != 1 {
			return deny("unexpected parameters on DeleteObjects")
		}
		return s.authorizeDeleteObjects(deleteBody)
	case method == http.MethodHead && len(query) == 0:
		return nil // HeadBucket reveals only that the bucket exists.
	case method == http.MethodGet && query.Has("uploads"):
		for name := range query {
			if name != "uploads" && name != "prefix" && name != "key-marker" && name != "upload-id-marker" && name != "max-uploads" && name != "delimiter" && name != "encoding-type" {
				return deny("query parameter %q is not allowed on ListMultipartUploads", name)
			}
		}
		if !s.containsListPrefix(query.Get("prefix")) {
			return deny("list prefix %q is outside prefix %q", query.Get("prefix"), s.Prefix)
		}
		return nil
	case method == http.MethodGet:
		for name := range query {
			if !listParams[name] {
				return deny("query parameter %q is not allowed on the bucket", name)
			}
		}
		if query.Get("encoding-type") != "" && query.Get("encoding-type") != "url" {
			return deny("unsupported encoding-type")
		}
		if !s.containsListPrefix(query.Get("prefix")) {
			return deny("list prefix %q is outside prefix %q", query.Get("prefix"), s.Prefix)
		}
		// start-after only positions the listing; results stay filtered
		// by prefix, so it cannot widen what is returned.
		return nil
	default:
		return deny("bucket-level %s is not allowed", method)
	}
}

// deleteObjects is the S3 DeleteObjects request body.
type deleteObjects struct {
	Objects []struct {
		Key       string `xml:"Key"`
		VersionID string `xml:"VersionId"`
	} `xml:"Object"`
}

func (s Scope) authorizeDeleteObjects(body []byte) error {
	var parsed deleteObjects
	if err := xml.Unmarshal(body, &parsed); err != nil {
		return deny("malformed DeleteObjects body: %v", err)
	}
	if len(parsed.Objects) == 0 {
		return deny("empty DeleteObjects body")
	}
	for _, object := range parsed.Objects {
		if object.VersionID != "" {
			return deny("versioned delete is not allowed")
		}
		if !s.contains(object.Key) {
			return deny("delete key %q is outside prefix %q", object.Key, s.Prefix)
		}
	}
	return nil
}

// authorizeCopySource checks CopyObject / UploadPartCopy sources:
// "bucket/key" or "/bucket/key", URL-encoded, optionally "?versionId=".
func (s Scope) authorizeCopySource(source string) error {
	path, query, _ := strings.Cut(source, "?")
	if query != "" {
		return deny("versioned copy source is not allowed")
	}
	decoded, err := url.PathUnescape(strings.TrimPrefix(path, "/"))
	if err != nil {
		return deny("malformed copy source")
	}
	bucket, key, _ := strings.Cut(decoded, "/")
	if bucket != s.Bucket || !s.contains(key) {
		return deny("copy source %q is outside the tenant scope", decoded)
	}
	return nil
}

// splitPath parses a path-style URL into bucket and key, returning the
// key both decoded (for policy) and as the caller escaped it (to forward).
func splitPath(u *url.URL) (bucket, key, escapedKey string, err error) {
	escaped := strings.TrimPrefix(u.EscapedPath(), "/")
	escapedBucket, escapedKey, _ := strings.Cut(escaped, "/")
	if bucket, err = url.PathUnescape(escapedBucket); err != nil || bucket == "" {
		return "", "", "", errors.New("malformed or missing bucket in path (path-style addressing is required)")
	}
	if key, err = url.PathUnescape(escapedKey); err != nil {
		return "", "", "", errors.New("malformed key")
	}
	return bucket, key, escapedKey, nil
}
