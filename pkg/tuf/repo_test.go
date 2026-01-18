// Copyright 2022 The Sigstore Authors
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

package tuf

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"net/http/httptest"

	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/theupdateframework/go-tuf"
	"knative.dev/pkg/logging"
)

const (
	fulcioRootCert = `-----BEGIN CERTIFICATE-----
MIICNzCCAd2gAwIBAgITPLBoBQhl1hqFND9S+SGWbfzaRTAKBggqhkjOPQQDAjBo
MQswCQYDVQQGEwJVSzESMBAGA1UECBMJV2lsdHNoaXJlMRMwEQYDVQQHEwpDaGlw
cGVuaGFtMQ8wDQYDVQQKEwZSZWRIYXQxDDAKBgNVBAsTA0NUTzERMA8GA1UEAxMI
dGVzdGNlcnQwHhcNMjEwMzEyMjMyNDQ5WhcNMzEwMjI4MjMyNDQ5WjBoMQswCQYD
VQQGEwJVSzESMBAGA1UECBMJV2lsdHNoaXJlMRMwEQYDVQQHEwpDaGlwcGVuaGFt
MQ8wDQYDVQQKEwZSZWRIYXQxDDAKBgNVBAsTA0NUTzERMA8GA1UEAxMIdGVzdGNl
cnQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQRn+Alyof6xP3GQClSwgV0NFuY
YEwmKP/WLWr/LwB6LUYzt5v49RlqG83KuaJSpeOj7G7MVABdpIZYWwqAiZV3o2Yw
ZDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBATAdBgNVHQ4EFgQU
T8Jwm6JuVb0dsiuHUROiHOOVHVkwHwYDVR0jBBgwFoAUT8Jwm6JuVb0dsiuHUROi
HOOVHVkwCgYIKoZIzj0EAwIDSAAwRQIhAJkNZmP6sKA+8EebRXFkBa9DPjacBpTc
OljJotvKidRhAiAuNrIazKEw2G4dw8x1z6EYk9G+7fJP5m93bjm/JfMBtA==
-----END CERTIFICATE-----`

	ctlogPublicKey = `-----BEGIN RSA PUBLIC KEY-----
MIICCgKCAgEAu1Ah4n2P8JGt92Qg86FdR8f1pou43yndggMuRCX0JB+bLn1rUFRA
KQVd+xnnd4PXJLLdml8ZohCr0lhBuMxZ7zBzt0T98kblUCxBgABPNpWIkTgacyC8
MlIYY/yBSuDWAJOA5IKi4Hh9nI+Mmb/FXgbOz5a5mZx8w7pMiTMu0+Rd9cPzRkUZ
DQfZsLONr6PwmyCAIL1oK80fevxKZPME0UV8bFPWnRxeVaFr5ddd/DOenV8H6SPy
r4ODbSOItpl53y6Az0m3FTIUf8cSsyR7dfE4zpA3M4djjtoKDNFRsTjU2RWVQW9X
MaxzznGVGhLEwkC+sYjR5NQvH5iiRvV18q+CGQqNX2+WWM3SPuty3nc86RBNR0FO
gSQA0TL2OAs6bJNmfzcwZxAKYbj7/88tj6qrjLaQtFTbBm2a7+TAQfs3UTiQi00z
EDYqeSj2WQvacNm1dWEAyx0QNLHiKGTn4TShGj8LUoGyjJ26Y6VPsotvCoj8jM0e
aN8Pc9/AYywVI+QktjaPZa7KGH3XJHJkTIQQRcUxOtDstKpcriAefDs8jjL5ju9t
5J3qEvgzmclNJKRnla4p3maM0vk+8cC7EXMV4P1zuCwr3akaHFJo5Y0aFhKsnHqT
c70LfiFo//8/QsvyjLIUtEWHTkGeuf4PpbYXr5qpJ6tWhG2MARxdeg8CAwEAAQ==
-----END RSA PUBLIC KEY-----`

	rekorPublicKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEF6j2sTItLcs0wKoOpMzI+9lJmCzf
N6mY2prOeaBRV2dnsJzC94hOxkM5pSp9nbAK1TBOI45fOOPsH2rSR++HrA==
-----END PUBLIC KEY-----`

	// validRepository is a valid tar/gzipped repository representing an air-gap
	// TUF repository.
	validRepository = `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`

	// IMPORTANT: The next expiration is on '2026-07-18T08:24:13Z'
	// Steps to generate:
	// 1. cgit clone github.com/sigstore/scaffolding
	// 2. run ./hack/setup-kind.sh
	// 3. export KO_DOCKER_REPO=registry.local:5001/sigstore
	// 4. run ./hack/setup-scaffolding.sh
	// 5. get the secrets from the kind cluster
	//    kubectl get secrets -o yaml -n tuf-system tuf-root
	rootJSON = `ewogInNpZ25lZCI6IHsKICAiX3R5cGUiOiAicm9vdCIsCiAgInNwZWNfdmVyc2lvbiI6ICIxLjAiLAogICJ2ZXJzaW9uIjogMSwKICAiZXhwaXJlcyI6ICIyMDI2LTA3LTE4VDA4OjI0OjEzWiIsCiAgImtleXMiOiB7CiAgICIwZjA1MmFkMzk5NTYwZDc1YzQzZjgwZGQ0NGZjZjZhMTBjNDk3MWZiYTczNTE3YTA2M2FhYjI3MTQwNjc2NjI4IjogewogICAgImtleXR5cGUiOiAiZWQyNTUxOSIsCiAgICAic2NoZW1lIjogImVkMjU1MTkiLAogICAgImtleWlkX2hhc2hfYWxnb3JpdGhtcyI6IFsKICAgICAic2hhMjU2IiwKICAgICAic2hhNTEyIgogICAgXSwKICAgICJrZXl2YWwiOiB7CiAgICAgInB1YmxpYyI6ICIwMWZiZjZlZDMxZjRhNjBmNGRkYzIwNjg0YzliNmE2MjIxMGY3Y2M4MWJmMzdjOGFiYjJmMThlMjUxOGExYzU5IgogICAgfQogICB9LAogICAiNDdmMjJjNmFlODI5MjlmNjU3ZTU2MmVmNWE1ZjdhNDRkYWI5ZjJhNDIzZWE2MGM5NjNiZWYzZjVhNjc5YTViOCI6IHsKICAgICJrZXl0eXBlIjogImVkMjU1MTkiLAogICAgInNjaGVtZSI6ICJlZDI1NTE5IiwKICAgICJrZXlpZF9oYXNoX2FsZ29yaXRobXMiOiBbCiAgICAgInNoYTI1NiIsCiAgICAgInNoYTUxMiIKICAgIF0sCiAgICAia2V5dmFsIjogewogICAgICJwdWJsaWMiOiAiOGNhMDRmOTIxYjc0MjI0ZTNjN2I4ZmRhMGQ4ZTFjMGE0MGQyOWU5ZGRhYTQwNjgyNjhjNmUxZTk0NWZlN2IzMyIKICAgIH0KICAgfSwKICAgIjk4MzYyYTNiNGE5OTQyODRjNWI3MjUwN2Q3MzhlY2RkZTgyNzNlMmNmZTQ2NjM5Y2JlZmVjMTJkNzdhYjNjODEiOiB7CiAgICAia2V5dHlwZSI6ICJlZDI1NTE5IiwKICAgICJzY2hlbWUiOiAiZWQyNTUxOSIsCiAgICAia2V5aWRfaGFzaF9hbGdvcml0aG1zIjogWwogICAgICJzaGEyNTYiLAogICAgICJzaGE1MTIiCiAgICBdLAogICAgImtleXZhbCI6IHsKICAgICAicHVibGljIjogImI0MjI1OWNlYjBhOTI5ZTdmMGUzNGRlN2M2ZjEwMTQ1NjI4NzhjNTMxZjFjY2E4OTAwODg2MjcyM2YwNjA0ZTMiCiAgICB9CiAgIH0sCiAgICJiNTJlMzhiODdmY2Q4NmJlZmQxNDZiMDVjOTBjMDIxYThmOGFjNGMxMmY3MzdlOTU0ODhmNWM0NzMyZTE3NmJlIjogewogICAgImtleXR5cGUiOiAiZWQyNTUxOSIsCiAgICAic2NoZW1lIjogImVkMjU1MTkiLAogICAgImtleWlkX2hhc2hfYWxnb3JpdGhtcyI6IFsKICAgICAic2hhMjU2IiwKICAgICAic2hhNTEyIgogICAgXSwKICAgICJrZXl2YWwiOiB7CiAgICAgInB1YmxpYyI6ICI2NjZhMTUwYjM4MjRjNzZkMGIxZmQxMmI0ZjA3OGQ1NmE0MTNlYmM3ZTUyYWYyN2VhNDE0M2RjNWZlZmU5ZWJkIgogICAgfQogICB9CiAgfSwKICAicm9sZXMiOiB7CiAgICJyb290IjogewogICAgImtleWlkcyI6IFsKICAgICAiOTgzNjJhM2I0YTk5NDI4NGM1YjcyNTA3ZDczOGVjZGRlODI3M2UyY2ZlNDY2MzljYmVmZWMxMmQ3N2FiM2M4MSIKICAgIF0sCiAgICAidGhyZXNob2xkIjogMQogICB9LAogICAic25hcHNob3QiOiB7CiAgICAia2V5aWRzIjogWwogICAgICJiNTJlMzhiODdmY2Q4NmJlZmQxNDZiMDVjOTBjMDIxYThmOGFjNGMxMmY3MzdlOTU0ODhmNWM0NzMyZTE3NmJlIgogICAgXSwKICAgICJ0aHJlc2hvbGQiOiAxCiAgIH0sCiAgICJ0YXJnZXRzIjogewogICAgImtleWlkcyI6IFsKICAgICAiNDdmMjJjNmFlODI5MjlmNjU3ZTU2MmVmNWE1ZjdhNDRkYWI5ZjJhNDIzZWE2MGM5NjNiZWYzZjVhNjc5YTViOCIKICAgIF0sCiAgICAidGhyZXNob2xkIjogMQogICB9LAogICAidGltZXN0YW1wIjogewogICAgImtleWlkcyI6IFsKICAgICAiMGYwNTJhZDM5OTU2MGQ3NWM0M2Y4MGRkNDRmY2Y2YTEwYzQ5NzFmYmE3MzUxN2EwNjNhYWIyNzE0MDY3NjYyOCIKICAgIF0sCiAgICAidGhyZXNob2xkIjogMQogICB9CiAgfSwKICAiY29uc2lzdGVudF9zbmFwc2hvdCI6IHRydWUKIH0sCiAic2lnbmF0dXJlcyI6IFsKICB7CiAgICJrZXlpZCI6ICI5ODM2MmEzYjRhOTk0Mjg0YzViNzI1MDdkNzM4ZWNkZGU4MjczZTJjZmU0NjYzOWNiZWZlYzEyZDc3YWIzYzgxIiwKICAgInNpZyI6ICIzMjIyYzY2YmNlZGY4YmM2YTlkMGRjMzJkMmZlNWM4Yzg1OTlkYmZiODk0OGE3NDRhMzBhN2U2YmQ2MjgyOTliODY2NzQ4NjQ0NDYyMzZhNTllNjc0MmQyMjM2ZTM4YzJiNTZmNzg2YjNkMjU3ZGIyZTZlZDJjMjM4M2M3MzQwNSIKICB9CiBdCn0=`
)

func TestCompressUncompressFS(t *testing.T) {
	files := map[string][]byte{
		"fulcio_v1.crt.pem": []byte(fulcioRootCert),
		"ctfe.pub":          []byte(ctlogPublicKey),
		"rekor.pub":         []byte(rekorPublicKey),
	}
	repo, dir, err := createRepo(context.Background(), files)
	if err != nil {
		t.Fatalf("Failed to CreateRepo: %s", err)
	}
	defer os.RemoveAll(dir)

	var buf bytes.Buffer
	fsys := os.DirFS(dir)
	if err = CompressFS(fsys, &buf, map[string]bool{"keys": true, "staged": true}); err != nil {
		t.Fatalf("Failed to compress: %v", err)
	}
	os.WriteFile("/tmp/newcompressed", buf.Bytes(), os.ModePerm)
	dstDir := t.TempDir()
	if err = Uncompress(&buf, dstDir); err != nil {
		t.Fatalf("Failed to uncompress: %v", err)
	}
	// Then check that files have been uncompressed there.
	meta, err := repo.GetMeta()
	if err != nil {
		t.Errorf("Failed to GetMeta: %s", err)
	}
	root := meta["root.json"]

	// This should have roundtripped to the new directory.
	rtRoot, err := os.ReadFile(filepath.Join(dstDir, "repository", "root.json"))
	if err != nil {
		t.Errorf("Failed to read the roundtripped root %v", err)
	}
	if !bytes.Equal(root, rtRoot) {
		t.Errorf("Roundtripped root differs:\n%s\n%s", string(root), string(rtRoot))
	}

	// As well as, say rekor.pub under targets dir
	rtRekor, err := os.ReadFile(filepath.Join(dstDir, "repository", "targets", "rekor.pub"))
	if err != nil {
		t.Errorf("Failed to read the roundtripped rekor %v", err)
	}
	if !bytes.Equal(files["rekor.pub"], rtRekor) {
		t.Errorf("Roundtripped rekor differs:\n%s\n%s", rekorPublicKey, string(rtRekor))
	}
}

func createRepo(ctx context.Context, files map[string][]byte) (tuf.LocalStore, string, error) {
	// TODO: Make this an in-memory fileystem.
	//	tmpDir := os.TempDir()
	//	dir := tmpDir + "tuf"
	dir := "/tmp/tuf"
	err := os.Mkdir(dir, os.ModePerm)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create tmp TUF dir: %w", err)
	}
	dir += "/"
	logging.FromContext(ctx).Infof("Creating the FS in %q", dir)
	local := tuf.FileSystemStore(dir, nil)

	// Create and commit a new TUF repo with the targets to the store.
	logging.FromContext(ctx).Infof("Creating new repo in %q", dir)
	r, err := tuf.NewRepoIndent(local, "", " ")
	if err != nil {
		return nil, "", fmt.Errorf("failed to NewRepoIndent: %w", err)
	}

	// Added by vaikas
	if err := r.Init(false); err != nil {
		return nil, "", fmt.Errorf("failed to Init repo: %w", err)
	}

	// Make all metadata files expire in 6 months.
	expires := time.Now().AddDate(0, 6, 0)

	for _, role := range []string{"root", "targets", "snapshot", "timestamp"} {
		_, err := r.GenKeyWithExpires(role, expires)
		if err != nil {
			return nil, "", fmt.Errorf("failed to GenKeyWithExpires: %w", err)
		}
	}

	targets := make([]string, 0, len(files))
	for k, v := range files {
		logging.FromContext(ctx).Infof("Adding %s file", k)
		if err := writeStagedTarget(dir, k, v); err != nil {
			return nil, "", fmt.Errorf("failed to write staged target %s: %w", k, err)
		}
		targets = append(targets, k)
	}
	err = r.AddTargetsWithExpires(targets, nil, expires)
	if err != nil {
		return nil, "", fmt.Errorf("failed to add AddTargetsWithExpires: %w", err)
	}

	// Snapshot, Timestamp, and Publish the repository.
	if err := r.SnapshotWithExpires(expires); err != nil {
		return nil, "", fmt.Errorf("failed to add SnapShotWithExpires: %w", err)
	}
	if err := r.TimestampWithExpires(expires); err != nil {
		return nil, "", fmt.Errorf("failed to add TimestampWithExpires: %w", err)
	}
	if err := r.Commit(); err != nil {
		return nil, "", fmt.Errorf("failed to Commit: %w", err)
	}
	return local, dir, nil
}

func writeStagedTarget(dir, path string, data []byte) error {
	path = filepath.Join(dir, "staged", "targets", path)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}

func TestClientFromSerializedMirror(t *testing.T) {
	repo, err := base64.StdEncoding.DecodeString(validRepository)
	if err != nil {
		t.Fatalf("failed to decode validrepository: %v", err)
	}
	root, err := base64.StdEncoding.DecodeString(rootJSON)
	if err != nil {
		t.Fatalf("failed to decode rootJSON: %v", err)
	}
	tufClient, err := ClientFromSerializedMirror(context.Background(), repo, root, "targets", "/repository/")
	if err != nil {
		t.Fatalf("Failed to unserialize repo: %v", err)
	}
	targets, err := tufClient.Targets()
	if err != nil {
		t.Errorf("failed to get Targets from tuf: %v", err)
	}
	if len(targets) == 0 {
		t.Errorf("Got no targets from the TUF client")
	}
}

func TestClientFromRemoteMirror(t *testing.T) {
	files := map[string][]byte{
		"fulcio_v1.crt.pem": []byte(fulcioRootCert),
		"ctfe.pub":          []byte(ctlogPublicKey),
		"rekor.pub":         []byte(rekorPublicKey),
	}
	local, dir, err := createRepo(context.Background(), files)
	if err != nil {
		t.Fatalf("Failed to CreateRepo: %s", err)
	}
	defer os.RemoveAll(dir)
	meta, err := local.GetMeta()
	if err != nil {
		t.Fatalf("getting meta: %v", err)
	}
	rootJSON, ok := meta["root.json"]
	if !ok {
		t.Fatalf("Getting root: %v", err)
	}
	serveDir := filepath.Join(dir, "repository")
	t.Logf("tuf repository was created in: %s serving tuf root at %s", dir, serveDir)
	fs := http.FileServer(http.Dir(serveDir))
	http.Handle("/", fs)

	ts := httptest.NewServer(fs)
	defer ts.Close()

	tufClient, err := ClientFromRemote(context.Background(), ts.URL, rootJSON, "targets")
	if err != nil {
		t.Fatalf("Failed to get client from remote: %v", err)
	}
	targets, err := tufClient.Targets()
	if err != nil {
		t.Errorf("failed to get Targets from tuf: %v", err)
	}
	if len(targets) == 0 {
		t.Errorf("Got no targets from the TUF client")
	}
}
