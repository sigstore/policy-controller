//
// Copyright 2024 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package registryauth

import (
	"context"
	"io"
	"time"

	ecr "github.com/awslabs/amazon-ecr-credential-helper/ecr-login"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/authn/k8schain"
	kauth "github.com/google/go-containerregistry/pkg/authn/kubernetes"
	"github.com/google/go-containerregistry/pkg/v1/google"
	"github.com/sigstore/policy-controller/pkg/webhook/registryauth/azure"
	"k8s.io/client-go/kubernetes"
	"knative.dev/pkg/logging"
)

/*
This file is based the K8s auth key chain constructor defined in the
go-containerregistry library in
https://github.com/google/go-containerregistry/blob/ff385a972813c79bbd5fc89357ff2cefe3e5b43c/pkg/authn/k8schain/k8schain.go

The ony difference in this implementation is the Azure key chain. It is created
using the current Azure credential handler defined in github.com/Azure/azure-sdk-for-go/sdk/azidentity.

The K8s auth key chain constructor in go-containerregistry uses an old Azure credential handler.
We should eventually try to get the Azure credential handler updated upstream in
go-containerregistry and remove this file. But for now, this custom constructor
should fix authentication errors encountered when using the policy controller
with ACR and AKS clusters.
*/

// Default cache size and TTL for ECR credentials
const (
	defaultECRCacheSize = 100
	defaultECRCacheTTL  = 6 * time.Hour
)

// getAmazonKeychain creates a keychain for AWS ECR with a bounded cache
func getAmazonKeychain(ctx context.Context) authn.Keychain {
	ecrCache, err := NewECRCredentialCache(defaultECRCacheSize, defaultECRCacheTTL)
	if err != nil {
		// Fall back to the old implementation if we can't create our bounded cache
		logging.FromContext(ctx).Warnf("Failed to create bounded ECR cache: %v, using unbounded cache", err)
		return authn.NewKeychainFromHelper(ecr.NewECRHelper(ecr.WithLogger(io.Discard)))
	}

	dockerHelper := NewDockerCredentialHelper(ecrCache)
	return authn.NewKeychainFromHelper(dockerHelper)
}

func NewK8sKeychain(ctx context.Context, client kubernetes.Interface, opt k8schain.Options) (authn.Keychain, error) {
	k8s, err := kauth.New(ctx, client, opt)
	if err != nil {
		return nil, err
	}

	// Use the bounded cache for ECR authentication
	amazonKeychain := getAmazonKeychain(ctx)

	return authn.NewMultiKeychain(
		k8s,
		authn.DefaultKeychain,
		google.Keychain,
		amazonKeychain,
		authn.NewKeychainFromHelper(azure.NewACRHelper()),
	), nil
}
