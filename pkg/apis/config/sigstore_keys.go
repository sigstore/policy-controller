//
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
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/pem"
	"fmt"

	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/policy-controller/pkg/apis/policy/v1alpha1"
	pbcommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	pbtrustroot "github.com/sigstore/protobuf-specs/gen/pb-go/trustroot/v1"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"
)

const (
	// SigstoreKeysConfigName is the name of ConfigMap created by the
	// reconciler and consumed by the admission webhook for determining
	// which Keys/Certificates are trusted for things like Fulcio/Rekor, etc.
	SigstoreKeysConfigName = "config-sigstore-keys"
)

// Type aliases for types from protobuf-specs. TODO: Consider just importing
// the protobuf-specs types directly from each package as needed.

// SigstoreKeys contains all the necessary Keys and Certificates for validating
// against a specific instance of Sigstore.
type SigstoreKeys = pbtrustroot.TrustedRoot
type CertificateAuthority = pbtrustroot.CertificateAuthority
type TransparencyLogInstance = pbtrustroot.TransparencyLogInstance
type DistinguishedName = pbcommon.DistinguishedName
type LogID = pbcommon.LogId
type TimeRange = pbcommon.TimeRange
type Timestamp = timestamppb.Timestamp

type SigstoreKeysMap struct {
	SigstoreKeys map[string]*SigstoreKeys
}

// NewSigstoreKeysFromMap creates a map of SigstoreKeys to use for validation.
func NewSigstoreKeysFromMap(data map[string]string) (*SigstoreKeysMap, error) {
	ret := make(map[string]*SigstoreKeys, len(data))
	// Spin through the ConfigMap. Each entry will have a serialized form of
	// necessary validation keys in the form of SigstoreKeys.
	for k, v := range data {
		// This is the example that we use to document / test the ConfigMap.
		if k == "_example" {
			continue
		}
		if v == "" {
			return nil, fmt.Errorf("configmap has an entry %q but no value", k)
		}
		sigstoreKeys := &SigstoreKeys{}

		if err := parseSigstoreKeys(v, sigstoreKeys); err != nil {
			return nil, fmt.Errorf("failed to parse the entry %q : %q : %w", k, v, err)
		}
		ret[k] = sigstoreKeys
	}
	return &SigstoreKeysMap{SigstoreKeys: ret}, nil
}

// NewImagePoliciesConfigFromConfigMap creates a Features from the supplied ConfigMap
func NewSigstoreKeysFromConfigMap(config *corev1.ConfigMap) (*SigstoreKeysMap, error) {
	return NewSigstoreKeysFromMap(config.Data)
}

func parseSigstoreKeys(entry string, out *pbtrustroot.TrustedRoot) error {
	j, err := yaml.YAMLToJSON([]byte(entry))
	if err != nil {
		return fmt.Errorf("config's value could not be converted to JSON: %w : %s", err, entry)
	}
	return protojson.Unmarshal(j, out)
}

// ConvertSigstoreKeys takes a source and converts into a SigstoreKeys suitable
// for serialization into a ConfigMap entry.
func ConvertSigstoreKeys(_ context.Context, source *v1alpha1.SigstoreKeys) *SigstoreKeys {
	sk := &SigstoreKeys{}
	sk.MediaType = "application/vnd.dev.sigstore.trustedroot+json;version=0.1"
	sk.CertificateAuthorities = make([]*pbtrustroot.CertificateAuthority, len(source.CertificateAuthorities))
	for i := range source.CertificateAuthorities {
		sk.CertificateAuthorities[i] = ConvertCertificateAuthority(source.CertificateAuthorities[i])
	}

	sk.Tlogs = make([]*pbtrustroot.TransparencyLogInstance, len(source.TLogs))
	for i := range source.TLogs {
		sk.Tlogs[i] = ConvertTransparencyLogInstance(source.TLogs[i])
	}

	sk.Ctlogs = make([]*pbtrustroot.TransparencyLogInstance, len(source.CTLogs))
	for i := range source.CTLogs {
		sk.Ctlogs[i] = ConvertTransparencyLogInstance(source.CTLogs[i])
	}

	sk.TimestampAuthorities = make([]*pbtrustroot.CertificateAuthority, len(source.TimeStampAuthorities))
	for i := range source.TimeStampAuthorities {
		sk.TimestampAuthorities[i] = ConvertCertificateAuthority(source.TimeStampAuthorities[i])
	}
	return sk
}

// ConvertCertificateAuthority converts public into private CertificateAuthority
func ConvertCertificateAuthority(source v1alpha1.CertificateAuthority) *pbtrustroot.CertificateAuthority {
	return &pbtrustroot.CertificateAuthority{
		Subject: &pbcommon.DistinguishedName{
			Organization: source.Subject.Organization,
			CommonName:   source.Subject.CommonName,
		},
		Uri:       source.URI.String(),
		CertChain: DeserializeCertChain(source.CertChain),
		ValidFor: &pbcommon.TimeRange{
			Start: &timestamppb.Timestamp{
				Seconds: 0, // TODO: Add support for time range to v1alpha1.CertificateAuthority
			},
		},
	}
}

// ConvertTransparencyLogInstance converts public into private
// TransparencyLogInstance.
func ConvertTransparencyLogInstance(source v1alpha1.TransparencyLogInstance) *pbtrustroot.TransparencyLogInstance {
	pbpk, pk, err := DeserializePublicKey(source.PublicKey)
	if err != nil {
		return nil // TODO: log error? Add return error?
	}
	logID, err := cosign.GetTransparencyLogID(pk)
	if err != nil {
		return nil // TODO: log error? Add return error?
	}

	return &pbtrustroot.TransparencyLogInstance{
		BaseUrl:       source.BaseURL.String(),
		HashAlgorithm: HashStringToHashAlgorithm(source.HashAlgorithm),
		PublicKey:     pbpk,
		LogId: &pbcommon.LogId{
			KeyId: []byte(logID),
		},
	}
}

func HashStringToHashAlgorithm(hash string) pbcommon.HashAlgorithm {
	switch hash {
	case "sha-256", "sha256":
		return pbcommon.HashAlgorithm_SHA2_256
	case "sha-384", "sha384":
		return pbcommon.HashAlgorithm_SHA2_384
	case "sha-512", "sha512":
		return pbcommon.HashAlgorithm_SHA2_512
	default:
		return pbcommon.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED
	}
}

func SerializeCertChain(certChain *pbcommon.X509CertificateChain) []byte {
	var chain []byte
	for _, cert := range certChain.Certificates {
		bytes := cert.RawBytes
		block := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: bytes,
		}
		chain = append(chain, pem.EncodeToMemory(block)...)
	}
	return chain
}

func SerializePublicKey(publicKey *pbcommon.PublicKey) []byte {
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKey.RawBytes,
	}
	return pem.EncodeToMemory(block)
}

func DeserializeCertChain(chain []byte) *pbcommon.X509CertificateChain {
	var certs []*pbcommon.X509Certificate
	for {
		var block *pem.Block
		block, chain = pem.Decode(chain)
		if block == nil {
			break
		}
		certs = append(certs, &pbcommon.X509Certificate{RawBytes: block.Bytes})
	}
	return &pbcommon.X509CertificateChain{Certificates: certs}
}

func DeserializePublicKey(publicKey []byte) (*pbcommon.PublicKey, crypto.PublicKey, error) {
	block, _ := pem.Decode(publicKey)
	if block == nil {
		return nil, nil, fmt.Errorf("failed to decode public key")
	}
	pk, err := cryptoutils.UnmarshalPEMToPublicKey(publicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal public key: %w", err)
	}
	var keyDetails pbcommon.PublicKeyDetails
	switch k := pk.(type) {
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			keyDetails = pbcommon.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256
		case elliptic.P384():
			keyDetails = pbcommon.PublicKeyDetails_PKIX_ECDSA_P384_SHA_384
		case elliptic.P521():
			keyDetails = pbcommon.PublicKeyDetails_PKIX_ECDSA_P521_SHA_512
		default:
			keyDetails = pbcommon.PublicKeyDetails_PUBLIC_KEY_DETAILS_UNSPECIFIED
		}
	case *rsa.PublicKey:
		switch k.Size() {
		case 2048:
			keyDetails = pbcommon.PublicKeyDetails_PKIX_RSA_PSS_2048_SHA256
		case 3072:
			keyDetails = pbcommon.PublicKeyDetails_PKIX_RSA_PSS_3072_SHA256
		case 4096:
			keyDetails = pbcommon.PublicKeyDetails_PKIX_RSA_PSS_4096_SHA256
		default:
			keyDetails = pbcommon.PublicKeyDetails_PUBLIC_KEY_DETAILS_UNSPECIFIED
		}
	default:
		keyDetails = pbcommon.PublicKeyDetails_PUBLIC_KEY_DETAILS_UNSPECIFIED
	}

	return &pbcommon.PublicKey{
		RawBytes:   block.Bytes,
		KeyDetails: keyDetails,
		ValidFor: &pbcommon.TimeRange{
			Start: &timestamppb.Timestamp{
				Seconds: 0, // TODO: Add support for time range to v1alpha.TransparencyLogInstance
			},
		},
	}, pk, nil
}
