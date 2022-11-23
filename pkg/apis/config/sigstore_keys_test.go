// Copyright 2022 The Sigstore Authors.
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

package config

import (
	"testing"

	. "knative.dev/pkg/configmap/testing"
	_ "knative.dev/pkg/system/testing"
)

const (
	rekorPublicKey = `-----BEGIN PUBLIC KEY-----
	MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7D2WvgqSzs9jpdJsOJ5Nl6xg8JXm
	Nmo7M3bN7+dQddw9Ibc2R3SV8tzBZw0rST8FKcn4apJepcKM4qUpYUeNfw==
	-----END PUBLIC KEY-----
	`
	tsaCertChain = `-----BEGIN CERTIFICATE-----
	MIIBzDCCAXKgAwIBAgIUfyGKDoFa7y6s/W1p1CiTmBRs1eAwCgYIKoZIzj0EAwIw
	MDEOMAwGA1UEChMFbG9jYWwxHjAcBgNVBAMTFVRlc3QgVFNBIEludGVybWVkaWF0
	ZTAeFw0yMjExMDkyMDMxMzRaFw0zMTExMDkyMDM0MzRaMDAxDjAMBgNVBAoTBWxv
	Y2FsMR4wHAYDVQQDExVUZXN0IFRTQSBUaW1lc3RhbXBpbmcwWTATBgcqhkjOPQIB
	BggqhkjOPQMBBwNCAAR3KcDy9jwARX0rDvyr+MGGkG3n1OA0MU5+ZiDmgusFyk6U
	6bovKWVMfD8J8NTcJZE0RaYJr8/dE9kgcIIXlhMwo2owaDAOBgNVHQ8BAf8EBAMC
	B4AwHQYDVR0OBBYEFHNn5R3b3MtUdSNrFO49Q6XDVSnkMB8GA1UdIwQYMBaAFNLS
	6gno7Om++Qt5zIa+H9o0HiT2MBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMAoGCCqG
	SM49BAMCA0gAMEUCIQCF0olohnvdUq6T7/wPk19Z5aQP/yxRTjCWYuhn/TCyHgIg
	azV3air4GRZbN9bdYtcQ7JUAKq89GOhtFfl6kcoVUvU=
	-----END CERTIFICATE-----
	-----BEGIN CERTIFICATE-----
	MIIB0jCCAXigAwIBAgIUXpBmYJFFaGW3cC8p6b/DHr1i8IowCgYIKoZIzj0EAwIw
	KDEOMAwGA1UEChMFbG9jYWwxFjAUBgNVBAMTDVRlc3QgVFNBIFJvb3QwHhcNMjIx
	MTA5MjAyOTM0WhcNMzIxMTA5MjAzNDM0WjAwMQ4wDAYDVQQKEwVsb2NhbDEeMBwG
	A1UEAxMVVGVzdCBUU0EgSW50ZXJtZWRpYXRlMFkwEwYHKoZIzj0CAQYIKoZIzj0D
	AQcDQgAEKDPDRIwDS1ZCymub6yanCG5ma0qDjLpNonDvooSkRHEgU0TNibeJn6M+
	5W608hCw8nwuucMbXQ41kNeuBeevyqN4MHYwDgYDVR0PAQH/BAQDAgEGMBMGA1Ud
	JQQMMAoGCCsGAQUFBwMIMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFNLS6gno
	7Om++Qt5zIa+H9o0HiT2MB8GA1UdIwQYMBaAFB1nvXpNK7AuQlbJ+ya6nPSqWi+T
	MAoGCCqGSM49BAMCA0gAMEUCIGiwqCI29w7C4V8TltCsi728s5DtklCPySDASUSu
	a5y5AiEA40Ifdlwf7Uj8q8NSD6Z4g/0js0tGNdLSUJ1do/WoN0s=
	-----END CERTIFICATE-----
	-----BEGIN CERTIFICATE-----
	MIIBlDCCATqgAwIBAgIUYZx9sS14En7SuHDOJJP4IPopMjUwCgYIKoZIzj0EAwIw
	KDEOMAwGA1UEChMFbG9jYWwxFjAUBgNVBAMTDVRlc3QgVFNBIFJvb3QwHhcNMjIx
	MTA5MjAyOTM0WhcNMzIxMTA5MjAzNDM0WjAoMQ4wDAYDVQQKEwVsb2NhbDEWMBQG
	A1UEAxMNVGVzdCBUU0EgUm9vdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABAbB
	B0SU8G75hVIUphChA4nfOwNWP347TjScIdsEPrKVn+/Y1HmmLHJDjSfn+xhEFoEk
	7jqgrqon48i4xbo7xAujQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTAD
	AQH/MB0GA1UdDgQWBBQdZ716TSuwLkJWyfsmupz0qlovkzAKBggqhkjOPQQDAgNI
	ADBFAiBe5P56foqmFcZAVpEeAOFZrAlEiq05CCpMNYh5EjLvmAIhAKNF6xIV5uFd
	pSTJsAwzjW78CKQm7qol0uPmPPu6mNaw
	-----END CERTIFICATE-----`
)

func TestDefaultsSigstoreKeysConfigurationFromFile(t *testing.T) {
	_, example := ConfigMapsFromTestFile(t, SigstoreKeysConfigName)
	keys, err := NewSigstoreKeysFromConfigMap(example)
	if err != nil {
		t.Error("NewSigstoreKeysFromConfigMap(example) =", err)
	}
	sigstoreKeys := keys["my-custom-sigstore-keys"]
	got := sigstoreKeys.CertificateAuthority[0].Subject.Organization
	if got != "fulcio-organization" {
		t.Errorf("Invalid organization, want foo got %s", got)
	}
	// TODO: Validate the entire file, above spot checks are not enough, but
	// at least we can unmarshal.
	// Note that even though sigstoreKeys.TLog[0].PublicKey is base64 encoded
	// in the ConfigMap it gets decoded when we fetch it above, so we get the
	// PEM format for it directly. Same for tsaCertChain
	got = string(sigstoreKeys.TLog[0].PublicKey)
	if got != rekorPublicKey {
		t.Errorf("Invalid public key, want %s got %s", rekorPublicKey, got)
	}
	got = string(sigstoreKeys.TimeStampAuthorities[0].CertChain)
	if got != tsaCertChain {
		t.Errorf("Invalid cert chain, want %s got %s", tsaCertChain, got)
	}
}
