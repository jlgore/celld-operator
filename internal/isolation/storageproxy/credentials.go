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
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// CredentialConfig is everything a credential source may need. Each source
// reads the fields it understands.
type CredentialConfig struct {
	Scope  Scope
	Region string

	// static
	Dir string

	// webIdentity
	RoleARN            string
	TokenFile          string
	STSEndpoint        string
	SessionDuration    time.Duration
	SessionName        string
	ScopeSessionPolicy bool
}

// CredentialSource builds a provider for the proxy. Sources are pluggable:
// register another one (a cloud's workload identity, Vault, ...) with
// RegisterCredentialSource and select it with --credential-source.
type CredentialSource func(CredentialConfig) (aws.CredentialsProvider, error)

var (
	sourcesMu sync.RWMutex
	sources   = map[string]CredentialSource{
		"static":      staticSource,
		"webIdentity": webIdentitySource,
	}
)

// RegisterCredentialSource adds or replaces a named source.
func RegisterCredentialSource(name string, source CredentialSource) {
	sourcesMu.Lock()
	defer sourcesMu.Unlock()
	sources[name] = source
}

// NewCredentials resolves a named source and wraps it in a refreshing cache.
func NewCredentials(name string, cfg CredentialConfig) (aws.CredentialsProvider, error) {
	sourcesMu.RLock()
	source, ok := sources[name]
	names := make([]string, 0, len(sources))
	for n := range sources {
		names = append(names, n)
	}
	sourcesMu.RUnlock()
	if !ok {
		slices.Sort(names)
		return nil, fmt.Errorf("unknown credential source %q (have %s)", name, strings.Join(names, ", "))
	}
	provider, err := source(cfg)
	if err != nil {
		return nil, err
	}
	return aws.NewCredentialsCache(provider, func(o *aws.CredentialsCacheOptions) {
		// Refresh well before expiry so a slow STS call never stalls a
		// lease renewal behind it.
		o.ExpiryWindow = 5 * time.Minute
		o.ExpiryWindowJitterFrac = 0.2
	}), nil
}

// staticSource reads a key pair from files (a mounted Secret). The files
// are re-read every minute, so a Secret rotation takes effect without a
// restart.
func staticSource(cfg CredentialConfig) (aws.CredentialsProvider, error) {
	if cfg.Dir == "" {
		return nil, fmt.Errorf("static credentials need --credentials-dir")
	}
	return aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		read := func(name string, required bool) (string, error) {
			raw, err := os.ReadFile(filepath.Join(cfg.Dir, name))
			if os.IsNotExist(err) && !required {
				return "", nil
			}
			return strings.TrimSpace(string(raw)), err
		}
		id, err := read("AWS_ACCESS_KEY_ID", true)
		if err != nil {
			return aws.Credentials{}, err
		}
		secret, err := read("AWS_SECRET_ACCESS_KEY", true)
		if err != nil {
			return aws.Credentials{}, err
		}
		token, err := read("AWS_SESSION_TOKEN", false)
		if err != nil {
			return aws.Credentials{}, err
		}
		return aws.Credentials{
			AccessKeyID: id, SecretAccessKey: secret, SessionToken: token, Source: "tenant-static",
			CanExpire: true, Expires: time.Now().Add(6 * time.Minute),
		}, nil
	}), nil
}

// webIdentitySource exchanges the proxy's projected ServiceAccount token
// for short-lived credentials (STS AssumeRoleWithWebIdentity). The token is
// audience-scoped and rotated by the kubelet; nothing long-lived exists.
func webIdentitySource(cfg CredentialConfig) (aws.CredentialsProvider, error) {
	if cfg.RoleARN == "" || cfg.TokenFile == "" {
		return nil, fmt.Errorf("webIdentity credentials need --role-arn and --token-file")
	}
	stsOptions := sts.Options{Region: cfg.Region}
	if cfg.STSEndpoint != "" {
		stsOptions.BaseEndpoint = aws.String(cfg.STSEndpoint)
	}
	client := sts.New(stsOptions)
	return stscreds.NewWebIdentityRoleProvider(client, cfg.RoleARN, stscreds.IdentityTokenFile(cfg.TokenFile),
		func(o *stscreds.WebIdentityRoleOptions) {
			o.RoleSessionName = cfg.SessionName
			if cfg.SessionDuration > 0 {
				o.Duration = cfg.SessionDuration
			}
			if cfg.ScopeSessionPolicy {
				o.Policy = aws.String(SessionPolicy(cfg.Scope))
			}
		}), nil
}

// SessionPolicy is an inline policy that narrows an assumed role to the
// tenant's prefix: the effective permission is the intersection of the role
// policy and this one, so a broad role still yields a prefix-scoped key.
func SessionPolicy(s Scope) string {
	objects := fmt.Sprintf("arn:aws:s3:::%s/%s/*", s.Bucket, s.Prefix)
	policy := map[string]any{
		"Version": "2012-10-17",
		"Statement": []any{
			map[string]any{
				"Effect": "Allow",
				"Action": []string{
					"s3:GetObject", "s3:PutObject", "s3:DeleteObject",
					"s3:AbortMultipartUpload", "s3:ListMultipartUploadParts",
				},
				"Resource": objects,
			},
			map[string]any{
				"Effect":   "Allow",
				"Action":   []string{"s3:ListBucket", "s3:ListBucketMultipartUploads"},
				"Resource": "arn:aws:s3:::" + s.Bucket,
				"Condition": map[string]any{
					"StringLike": map[string]any{"s3:prefix": []string{s.Prefix, s.Prefix + "/*"}},
				},
			},
		},
	}
	raw, _ := json.Marshal(policy)
	return string(raw)
}
