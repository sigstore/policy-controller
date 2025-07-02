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

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"log"
	"math/big"
	"os"
	"path"
	"path/filepath"
	"time"

	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/policy-controller/pkg/apis/config"
	testing "github.com/sigstore/policy-controller/pkg/reconciler/testing/v1alpha1"
	pbcommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/scaffolding/pkg/repo"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// This program generates test data for the trustroot reconciler.
//
// To run this program, you can use the following command from the root of the repo:
// $ go run hack/gentestdata/gentestdata.go
// or,
// $ make generate-testdata
//
// The output of this program can be used to update the `marshalledEntry.json`
// file in the `pkg/reconciler/trustroot/testdata` package.
//
// Do not rely on the output of this program to produce valid results. Always
// verify the output manually before committing.

var (
	dir = flag.String("output-dir", "pkg/reconciler/trustroot/testdata", "Output directory")
)

func main() {
	flag.Parse()
	ctfePK, ctfeLogID := genPK()
	rekorPK, rekorLogID := genPK()
	fulcioChain := genCertChain(x509.KeyUsage(x509.ExtKeyUsageCodeSigning))
	fulcioChainConcat := bytes.Join(fulcioChain, nil)
	tsaChain := genCertChain(x509.KeyUsage(x509.ExtKeyUsageTimeStamping))
	tsaChainConcat := bytes.Join(tsaChain, nil)

	sigstoreKeysMap := map[string]string{
		"ctfe":   string(ctfePK),
		"fulcio": string(fulcioChainConcat),
		"rekor":  string(rekorPK),
		"tsa":    string(tsaChainConcat),
	}
	marshalledEntry, err := genTrustRoot(sigstoreKeysMap)
	if err != nil {
		log.Fatal(err)
	}

	tufRepo, rootJSON, err := genTUFRepo(map[string][]byte{
		"rekor.pem":  []byte(sigstoreKeysMap["rekor"]),
		"ctfe.pem":   []byte(sigstoreKeysMap["ctfe"]),
		"fulcio.pem": []byte(sigstoreKeysMap["fulcio"]),
	})
	if err != nil {
		log.Fatal(err)
	}

	tufRepoWithTrustedRootJSON, rootJSONWithTrustedRootJSON, err := genTUFRepo(map[string][]byte{
		"trusted_root.json": marshalledEntry,
	})
	if err != nil {
		log.Fatal(err)
	}

	tufRepoWithCustomTrustedRootJSON, rootJSONWithCustomTrustedRootJSON, err := genTUFRepo(map[string][]byte{
		"custom_trusted_root.json": marshalledEntry,
	})
	if err != nil {
		log.Fatal(err)
	}

	marshalledEntryFromMirrorFS, err := genTrustedRoot(sigstoreKeysMap)
	if err != nil {
		log.Fatal(err)
	}

	mustWriteFile("ctfePublicKey.pem", ctfePK)
	mustWriteFile("ctfeLogID.txt", []byte(ctfeLogID))
	mustWriteFile("rekorPublicKey.pem", rekorPK)
	mustWriteFile("rekorLogID.txt", []byte(rekorLogID))
	mustWriteFile("fulcioCertChain.pem", fulcioChainConcat)
	mustWriteFile("tsaCertChain.pem", tsaChainConcat)
	mustWriteFile("marshalledEntry.json", marshalledEntry)
	mustWriteFile("marshalledEntryFromMirrorFS.json", marshalledEntryFromMirrorFS)
	mustWriteFile("tufRepo.tar", tufRepo)
	mustWriteFile("root.json", rootJSON)
	mustWriteFile("tufRepoWithTrustedRootJSON.tar", tufRepoWithTrustedRootJSON)
	mustWriteFile("rootWithTrustedRootJSON.json", rootJSONWithTrustedRootJSON)
	mustWriteFile("tufRepoWithCustomTrustedRootJSON.tar", tufRepoWithCustomTrustedRootJSON)
	mustWriteFile("rootWithCustomTrustedRootJSON.json", rootJSONWithCustomTrustedRootJSON)
}

func mustWriteFile(path string, data []byte) {
	err := os.WriteFile(filepath.Join(*dir, path), data, 0600)
	if err != nil {
		log.Fatalf("failed to write file %s: %v", path, err)
	}
}

func genPK() ([]byte, string) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("failed to generate ecdsa key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(priv.Public().(*ecdsa.PublicKey))
	if err != nil {
		log.Fatalf("failed to marshal ecdsa key: %v", err)
	}
	pemPK := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})

	// generate log id
	pk, err := cryptoutils.UnmarshalPEMToPublicKey(pemPK)
	if err != nil {
		log.Fatalf("failed to unmarshal ecdsa key: %v", err)
	}
	logID, err := cosign.GetTransparencyLogID(pk)
	if err != nil {
		log.Fatalf("failed to get transparency log id: %v", err)
	}
	return pemPK, logID
}

func genCertChain(keyUsage x509.KeyUsage) [][]byte {
	// Create a new CA certificate
	caPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("failed to generate ecdsa key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          new(big.Int).SetInt64(1),
		Subject:               pkix.Name{CommonName: "ca"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caCertBytes, err := x509.CreateCertificate(rand.Reader, template, template, caPriv.Public(), caPriv)
	if err != nil {
		log.Fatalf("failed to create x509 certificate: %v", err)
	}

	caCert, err := x509.ParseCertificate(caCertBytes)
	if err != nil {
		log.Fatalf("failed to parse x509 certificate: %v", err)
	}

	// Create a new leaf certificate
	leafPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("failed to generate ecdsa key: %v", err)
	}
	leafCert, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: new(big.Int).SetInt64(2),
		Subject:      pkix.Name{CommonName: "leaf"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     keyUsage,
	}, caCert, &leafPriv.PublicKey, caPriv)
	if err != nil {
		log.Fatalf("failed to create x509 certificate: %v", err)
	}

	return [][]byte{pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafCert}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertBytes})}
}

func genTrustRoot(sigstoreKeysMap map[string]string) (marshalledEntry []byte, err error) {
	trustRoot := testing.NewTrustRoot("test-trustroot", testing.WithSigstoreKeys(sigstoreKeysMap))
	sigstoreKeys, err := config.ConvertSigstoreKeys(context.Background(), trustRoot.Spec.SigstoreKeys)
	if err != nil {
		return nil, err
	}
	err = populateLogIDs(sigstoreKeys)
	if err != nil {
		return nil, err
	}
	return []byte(protojson.Format(sigstoreKeys)), nil
}

func populateLogIDs(sigstoreKeys *config.SigstoreKeys) error {
	for i := range sigstoreKeys.Tlogs {
		logID, err := genLogID(sigstoreKeys.Tlogs[i].PublicKey.RawBytes)
		if err != nil {
			return err
		}
		sigstoreKeys.Tlogs[i].CheckpointKeyId = &config.LogID{KeyId: []byte(logID)}
	}
	for i := range sigstoreKeys.Ctlogs {
		logID, err := genLogID(sigstoreKeys.Ctlogs[i].PublicKey.RawBytes)
		if err != nil {
			return err
		}
		sigstoreKeys.Ctlogs[i].CheckpointKeyId = &config.LogID{KeyId: []byte(logID)}
	}
	return nil
}

func genLogID(pkBytes []byte) (string, error) {
	pk, err := x509.ParsePKIXPublicKey(pkBytes)
	if err != nil {
		return "", err
	}
	return cosign.GetTransparencyLogID(pk)
}

func genTUFRepo(files map[string][]byte) ([]byte, []byte, error) {
	defer os.RemoveAll(path.Join(os.TempDir(), "tuf")) // TODO: Update scaffolding to use os.MkdirTemp and remove this
	ctx := context.Background()
	local, dir, err := repo.CreateRepoWithOptions(ctx, files, repo.CreateRepoOptions{AddMetadataTargets: true})
	if err != nil {
		return nil, nil, err
	}
	meta, err := local.GetMeta()
	if err != nil {
		return nil, nil, err
	}
	rootJSON, ok := meta["root.json"]
	if !ok {
		return nil, nil, err
	}

	var compressed bytes.Buffer
	if err := repo.CompressFS(os.DirFS(dir), &compressed, map[string]bool{"keys": true, "staged": true}); err != nil {
		return nil, nil, err
	}
	return compressed.Bytes(), rootJSON, nil
}

func genTrustedRoot(sigstoreKeysMap map[string]string) ([]byte, error) {
	tlogKey, _, err := config.DeserializePublicKey([]byte(sigstoreKeysMap["rekor"]))
	if err != nil {
		return nil, err
	}
	ctlogKey, _, err := config.DeserializePublicKey([]byte(sigstoreKeysMap["ctfe"]))
	if err != nil {
		return nil, err
	}
	certChain, err := config.DeserializeCertChain([]byte(sigstoreKeysMap["fulcio"]))
	if err != nil {
		return nil, err
	}

	trustRoot := &config.SigstoreKeys{
		CertificateAuthorities: []*config.CertificateAuthority{{
			CertChain: certChain,
			ValidFor:  &config.TimeRange{Start: &timestamppb.Timestamp{}},
		}},
		Tlogs: []*config.TransparencyLogInstance{{
			HashAlgorithm: pbcommon.HashAlgorithm_SHA2_256,
			PublicKey:     tlogKey,
		}},
		Ctlogs: []*config.TransparencyLogInstance{{
			HashAlgorithm: pbcommon.HashAlgorithm_SHA2_256,
			PublicKey:     ctlogKey,
		}},
	}
	err = populateLogIDs(trustRoot)
	if err != nil {
		return nil, err
	}
	trustRootBytes := []byte(protojson.Format(trustRoot))
	return trustRootBytes, nil
}
