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
	"encoding/pem"
	"fmt"

	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/policy-controller/pkg/apis/policy/v1alpha1"
	pbcommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	pbtrustroot "github.com/sigstore/protobuf-specs/gen/pb-go/trustroot/v1"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"google.golang.org/protobuf/encoding/protojson"
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
type LogId = pbcommon.LogId

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
	}
}

// ConvertTransparencyLogInstance converts public into private
// TransparencyLogInstance.
func ConvertTransparencyLogInstance(source v1alpha1.TransparencyLogInstance) *pbtrustroot.TransparencyLogInstance {
	pk, err := cryptoutils.UnmarshalPEMToPublicKey(source.PublicKey)
	if err != nil {
		return nil // TODO: log error? Add return error?
	}
	logID, err := cosign.GetTransparencyLogID(pk)
	if err != nil {
		return nil // TODO: log error? Add return error?
	}

	var hashAlgorithm pbcommon.HashAlgorithm
	switch source.HashAlgorithm {
	case "sha256":
		hashAlgorithm = pbcommon.HashAlgorithm_SHA2_256
	case "sha384":
		hashAlgorithm = pbcommon.HashAlgorithm_SHA2_384
	case "sha512":
		hashAlgorithm = pbcommon.HashAlgorithm_SHA2_512
	default:
		hashAlgorithm = pbcommon.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED
	}

	return &pbtrustroot.TransparencyLogInstance{
		BaseUrl:       source.BaseURL.String(),
		HashAlgorithm: hashAlgorithm,
		PublicKey:     DeserializePublicKey(source.PublicKey),
		LogId: &pbcommon.LogId{
			KeyId: []byte(logID),
		},
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

func DeserializePublicKey(publicKey []byte) *pbcommon.PublicKey {
	block, _ := pem.Decode(publicKey)
	return &pbcommon.PublicKey{RawBytes: block.Bytes}
}
