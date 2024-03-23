// Copyright 2024 The Sigstore Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
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
	"encoding/json"
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
	"github.com/sigstore/scaffolding/pkg/repo"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
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

	marshalledEntryFromMirrorFS, tufRepo, rootJSON, err := genTUFRepo(sigstoreKeysMap)
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
	sigstoreKeys := &config.SigstoreKeys{}
	sigstoreKeys.ConvertFrom(context.Background(), trustRoot.Spec.SigstoreKeys)
	err = populateLogIDs(sigstoreKeys)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(sigstoreKeys, "", "  ")
}

func populateLogIDs(sigstoreKeys *config.SigstoreKeys) error {
	for i := range sigstoreKeys.TLogs {
		logID, err := genLogID(sigstoreKeys.TLogs[i].PublicKey)
		if err != nil {
			return err
		}
		sigstoreKeys.TLogs[i].LogID = logID
	}
	for i := range sigstoreKeys.CTLogs {
		logID, err := genLogID(sigstoreKeys.CTLogs[i].PublicKey)
		if err != nil {
			return err
		}
		sigstoreKeys.CTLogs[i].LogID = logID
	}
	return nil
}

func genLogID(pkBytes []byte) (string, error) {
	pk, err := cryptoutils.UnmarshalPEMToPublicKey(pkBytes)
	if err != nil {
		return "", err
	}
	return cosign.GetTransparencyLogID(pk)
}

func genTUFRepo(sigstoreKeysMap map[string]string) ([]byte, []byte, []byte, error) {
	files := map[string][]byte{}
	files["rekor.pem"] = []byte(sigstoreKeysMap["rekor"])
	files["ctfe.pem"] = []byte(sigstoreKeysMap["ctfe"])
	files["fulcio.pem"] = []byte(sigstoreKeysMap["fulcio"])

	defer os.RemoveAll(path.Join(os.TempDir(), "tuf")) // TODO: Update scaffolding to use os.MkdirTemp and remove this
	ctx := context.Background()
	local, dir, err := repo.CreateRepo(ctx, files)
	if err != nil {
		return nil, nil, nil, err
	}
	meta, err := local.GetMeta()
	if err != nil {
		return nil, nil, nil, err
	}
	rootJSON, ok := meta["root.json"]
	if !ok {
		return nil, nil, nil, err
	}

	var compressed bytes.Buffer
	if err := repo.CompressFS(os.DirFS(dir), &compressed, map[string]bool{"keys": true, "staged": true}); err != nil {
		return nil, nil, nil, err
	}

	trustRoot := &config.SigstoreKeys{
		CertificateAuthorities: []config.CertificateAuthority{{CertChain: []byte(sigstoreKeysMap["fulcio"])}},
		TLogs:                  []config.TransparencyLogInstance{{PublicKey: []byte(sigstoreKeysMap["rekor"])}},
		CTLogs:                 []config.TransparencyLogInstance{{PublicKey: []byte(sigstoreKeysMap["ctfe"])}},
	}
	err = populateLogIDs(trustRoot)
	if err != nil {
		return nil, nil, nil, err
	}
	trustRootBytes, err := json.MarshalIndent(trustRoot, "", "  ")
	if err != nil {
		return nil, nil, nil, err
	}
	return trustRootBytes, compressed.Bytes(), rootJSON, nil
}
