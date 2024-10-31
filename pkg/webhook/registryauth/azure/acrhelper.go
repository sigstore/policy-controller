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

package azure

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/Azure/azure-sdk-for-go/profiles/preview/preview/containerregistry/runtime/containerregistry"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/docker/docker-credential-helpers/credentials"
)

type ACRHelper struct{}

func NewACRHelper() credentials.Helper {
	return &ACRHelper{}
}

func (a ACRHelper) Add(_ *credentials.Credentials) error {
	return fmt.Errorf("add is unimplemented")
}

func (a ACRHelper) Delete(_ string) error {
	return fmt.Errorf("delete is unimplemented")
}

func (a ACRHelper) Get(registryURL string) (string, string, error) {
	if !isACR(registryURL) {
		return "", "", fmt.Errorf("not an ACR registry")
	}

	azCred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return "", "", fmt.Errorf("failed to obtain a credential: %w", err)
	}

	// We need to set the desired token policy to https://management.azure.com
	// to get a token that can be used to authenticate to the Azure Container Registry.
	opts := policy.TokenRequestOptions{
		Scopes: []string{"https://management.azure.com/.default"},
	}
	accessToken, err := azCred.GetToken(context.Background(), opts)
	if err != nil {
		return "", "", fmt.Errorf("failed to get token: %w", err)
	}

	registryWithScheme, err := url.Parse(fmt.Sprintf("https://%s", registryURL))
	if err != nil {
		return "", "", fmt.Errorf("failed to parse registry URL: %w", err)
	}

	tenantID := os.Getenv("AZURE_TENANT_ID")
	if tenantID == "" {
		return "", "", fmt.Errorf("AZURE_TENANT_ID environment variable not found")
	}

	repoClient := containerregistry.NewRefreshTokensClient(registryWithScheme.String())
	refreshToken, err := repoClient.GetFromExchange(context.Background(), "access_token", registryURL, tenantID, "", accessToken.Token)
	if err != nil {
		return "", "", fmt.Errorf("failed to get refresh token: %w", err)
	}

	// we use a special username when authenticating with ACR using an access token
	// associated with a managed identity
	return "00000000-0000-0000-0000-000000000000", *refreshToken.RefreshToken, nil
}

func (a ACRHelper) List() (map[string]string, error) {
	return nil, fmt.Errorf("list is unimplemented")
}

func isACR(registryURL string) bool {
	return strings.HasSuffix(registryURL, ".azurecr.io")
}
