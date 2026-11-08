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
	"fmt"
	"slices"

	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// TokenReviewer authenticates tokens against the Kubernetes API server.
// Requiring the gateway's own audience means a token minted for anything
// else (the default API audience, another tenant's gateway) is refused.
type TokenReviewer struct {
	Client   kubernetes.Interface
	Audience string
}

func (t TokenReviewer) Review(ctx context.Context, token string) (string, error) {
	review, err := t.Client.AuthenticationV1().TokenReviews().Create(ctx, &authenticationv1.TokenReview{
		Spec: authenticationv1.TokenReviewSpec{Token: token, Audiences: []string{t.Audience}},
	}, metav1.CreateOptions{})
	if err != nil {
		return "", fmt.Errorf("token review: %w", err)
	}
	if !review.Status.Authenticated || !slices.Contains(review.Status.Audiences, t.Audience) {
		return "", ErrUnauthenticated
	}
	return review.Status.User.Username, nil
}
