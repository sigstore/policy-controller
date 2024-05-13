package registryauth

import (
	"context"
	"io"

	ecr "github.com/awslabs/amazon-ecr-credential-helper/ecr-login"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/authn/k8schain"
	kauth "github.com/google/go-containerregistry/pkg/authn/kubernetes"
	"github.com/google/go-containerregistry/pkg/v1/google"
	"github.com/sigstore/policy-controller/pkg/webhook/registryauth/azure"
	"k8s.io/client-go/kubernetes"
)

var amazonKeychain authn.Keychain = authn.NewKeychainFromHelper(ecr.NewECRHelper(ecr.WithLogger(io.Discard)))

func K8sChainWithCustomACRHelper(ctx context.Context, client kubernetes.Interface, opt k8schain.Options) (authn.Keychain, error) {
	k8s, err := kauth.New(ctx, client, kauth.Options(opt))
	if err != nil {
		return nil, err
	}

	return authn.NewMultiKeychain(
		k8s,
		authn.DefaultKeychain,
		google.Keychain,
		amazonKeychain,
		authn.NewKeychainFromHelper(azure.NewACRHelper()),
	), nil
}
