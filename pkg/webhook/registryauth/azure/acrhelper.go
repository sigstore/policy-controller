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

func (a ACRHelper) Get(_ string) (string, string, error) {
	azCred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return "", "", fmt.Errorf("failed to obtain a credential: %w", err)
	}

	opts := policy.TokenRequestOptions{
		Scopes: []string{"https://management.azure.com/.default"},
	}
	token, err := azCred.GetToken(context.Background(), opts)
	if err != nil {
		return "", "", fmt.Errorf("failed to get token: %w", err)
	}

	return token.Token, "", nil
}

func (a ACRHelper) List() (map[string]string, error) {
	return nil, fmt.Errorf("list is unimplemented")
}
