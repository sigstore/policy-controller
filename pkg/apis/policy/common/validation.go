package common

import (
	"strings"

	registryfuncs "github.com/google/go-containerregistry/pkg/name"
)

const (
	ociRepoDelimiter = "/"
)

func ValidateOCI(oci string) error {
	// We want to validate both registry uris only or registry with valid repository names
	parts := strings.SplitN(oci, ociRepoDelimiter, 2)
	if len(parts) == 2 && (strings.ContainsRune(parts[0], '.') || strings.ContainsRune(parts[0], ':')) {
		_, err := registryfuncs.NewRepository(oci, registryfuncs.StrictValidation)
		if err != nil {
			return err
		}
		return nil
	}
	_, err := registryfuncs.NewRegistry(oci, registryfuncs.StrictValidation)
	if err != nil {
		return err
	}
	return nil
}
