package azureauth

import (
	"context"
	"fmt"
	"log"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/docker/docker-credential-helpers/credentials"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/authn/k8schain"
	kauth "github.com/google/go-containerregistry/pkg/authn/kubernetes"
	"k8s.io/client-go/kubernetes"
)

type managedIdentityCreds struct {
	ClientID string
}

type CustomAzureAuthConfig struct {
	ManagedIdentity managedIdentityCreds
}

func (c *CustomAzureAuthConfig) UseManagedIdentity() bool {
	return c.ManagedIdentity.ClientID != ""
}

func (c *CustomAzureAuthConfig) GetManagedIdentityClientID() string {
	return c.ManagedIdentity.ClientID
}

func K8sChainWithCustomAzureCreds(ctx context.Context, client kubernetes.Interface, opt k8schain.Options, config CustomAzureAuthConfig) (authn.Keychain, error) {
	k8s, err := kauth.New(ctx, client, kauth.Options(opt))
	if err != nil {
		return nil, err
	}

	return authn.NewMultiKeychain(
		k8s,
		authn.DefaultKeychain,
		authn.NewKeychainFromHelper(NewACRHelper(config)),
	), nil

}

type ACRHelper struct {
	CustomAuthConfig CustomAzureAuthConfig
}

func NewACRHelper(config CustomAzureAuthConfig) credentials.Helper {
	return &ACRHelper{config}
}

func (a ACRHelper) Add(_ *credentials.Credentials) error {
	return fmt.Errorf("add is unimplemented")
}

func (a ACRHelper) Delete(_ string) error {
	return fmt.Errorf("delete is unimplemented")
}

func (a ACRHelper) Get(_ string) (string, string, error) {
	if a.CustomAuthConfig.UseManagedIdentity() {
		clientID := azidentity.ClientID(a.CustomAuthConfig.GetManagedIdentityClientID())
		credOpts := azidentity.ManagedIdentityCredentialOptions{
			ID: clientID,
		}
		azCred, err := azidentity.NewManagedIdentityCredential(&credOpts)
		if err != nil {
			log.Fatalf("failed to obtain a credential: %v", err)
		}

		opts := policy.TokenRequestOptions{
			Scopes: []string{"https://management.azure.com/.default"},
		}

		token, err := azCred.GetToken(context.Background(), opts)
		if err != nil {
			log.Fatalf("failed to get token: %v", err)
		}

		return token.Token, "", nil
	}

	azCred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}

	token, err := azCred.GetToken(context.Background(), policy.TokenRequestOptions{})
	if err != nil {
		log.Fatalf("failed to get token: %v", err)
	}

	return token.Token, "", nil
}

func (a ACRHelper) List() (map[string]string, error) {
	return nil, fmt.Errorf("list is unimplemented")
}
