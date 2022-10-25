package common

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestValidateOCI(t *testing.T) {
	tests := []struct {
		oci         string
		errorString string
		isError     bool
	}{
		{
			oci:     "gcr.io",
			isError: false,
		},
		{
			oci:         "gcr.io/test/*",
			errorString: "repository can only contain the characters `abcdefghijklmnopqrstuvwxyz0123456789_-./`: test/*",
			isError:     true,
		},
		{
			oci:         "gcr.@io/test",
			errorString: "registries must be valid RFC 3986 URI authorities: gcr.@io",
			isError:     true,
		},
		{
			oci:     "ghcr.io/sigstore/test",
			isError: false,
		},
		{
			oci:     "registry.example.com",
			isError: false,
		},
		{
			oci:     "localhost:8080/test",
			isError: false,
		},
		{
			oci:     "localhost",
			isError: false,
		},
	}

	for _, test := range tests {
		t.Run(test.oci, func(t *testing.T) {
			err := ValidateOCI(test.oci)
			if !test.isError && err != nil {
				t.Error("Unxpected error", err.Error())
			}
			if test.isError {
				if diff := cmp.Diff(test.errorString, err.Error()); diff != "" {
					t.Error("Unexpected error mesage (-want, +got):", diff)
				}
			}
		})
	}
}
