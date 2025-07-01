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

	// IMPORTANT: The next expiration is on '2026-01-01T11:46:29Z'
	// Steps to generate:
	// 1. cgit clone github.com/sigstore/scaffolding
	// 2. run ./hack/setup-kind.sh
	// 3. export KO_DOCKER_REPO=registry.local:5001/sigstore
	// 4. run ./hack/setup-scaffolding.sh
	// 5. get the secrets from the kind cluster
	//    kubectl get secrets -o yaml -n tuf-system tuf-root
	rootJSON = `ewogInNpZ25lZCI6IHsKICAiX3R5cGUiOiAicm9vdCIsCiAgInNwZWNfdmVyc2lvbiI6ICIxLjAiLAogICJ2ZXJzaW9uIjogMSwKICAiZXhwaXJlcyI6ICIyMDI2LTAxLTAxVDExOjQ2OjI5WiIsCiAgImtleXMiOiB7CiAgICIwZjhjNWYzNmZiNDMwNzEyMmZiNzk3MGUyMjRiNGUwODY0ZjRhZmE0ZTRmNjM0YmU3Nzg4ZTllYmQ5ZjI2Nzg1IjogewogICAgImtleXR5cGUiOiAiZWQyNTUxOSIsCiAgICAic2NoZW1lIjogImVkMjU1MTkiLAogICAgImtleWlkX2hhc2hfYWxnb3JpdGhtcyI6IFsKICAgICAic2hhMjU2IiwKICAgICAic2hhNTEyIgogICAgXSwKICAgICJrZXl2YWwiOiB7CiAgICAgInB1YmxpYyI6ICIzMWQ1MzNiMDJlNTgyNGI1NDEwYmNmMjI4NGZlNzVkMmZiNjdhMTA4Y2I1ZTdkNjhmOTc1YzljOWM1ODYyYzVjIgogICAgfQogICB9LAogICAiOTE4MmI1ODVlNzFiOTVmMDA1YzIyZWNkYjQwN2QxMDY5YTlkMjdiOGMzZmFmMzBmMmUxZmM5NTRhNWFkOWNmNiI6IHsKICAgICJrZXl0eXBlIjogImVkMjU1MTkiLAogICAgInNjaGVtZSI6ICJlZDI1NTE5IiwKICAgICJrZXlpZF9oYXNoX2FsZ29yaXRobXMiOiBbCiAgICAgInNoYTI1NiIsCiAgICAgInNoYTUxMiIKICAgIF0sCiAgICAia2V5dmFsIjogewogICAgICJwdWJsaWMiOiAiZTcxN2Y2NDY0YzMwYWFmMzVhOWE3MzgwY2M4NTkzNjRhNmMxNDgyOGRmNGE4MjJhNWRmYzA5ZTdjODJkMWIxZCIKICAgIH0KICAgfSwKICAgImU4YzZiMWQyMzA3NmYyOThhMTJjOTA4ZDlhODU3ZDFkZWU3MTI3NWQ1ZDdhNmVlOTQ2YTIzM2U4MzEwZjI3NmEiOiB7CiAgICAia2V5dHlwZSI6ICJlZDI1NTE5IiwKICAgICJzY2hlbWUiOiAiZWQyNTUxOSIsCiAgICAia2V5aWRfaGFzaF9hbGdvcml0aG1zIjogWwogICAgICJzaGEyNTYiLAogICAgICJzaGE1MTIiCiAgICBdLAogICAgImtleXZhbCI6IHsKICAgICAicHVibGljIjogIjU0Y2FlMzk2MzFjYmFiYmZmM2RlYjhmMzQ1ZjczMGU3ZmI3YjhkOGNlMTY3ZWZiOGNlMzg3YzQxMTIxOTg3ZjQiCiAgICB9CiAgIH0sCiAgICJmNWYzMTMzYjcwMzljYTMzZjk2ZDI5OTMzN2Q1ZTQyNWVhNzk4MzIyMDEzNjY5OWJlODhhZjU2NWU5NmIyZWVhIjogewogICAgImtleXR5cGUiOiAiZWQyNTUxOSIsCiAgICAic2NoZW1lIjogImVkMjU1MTkiLAogICAgImtleWlkX2hhc2hfYWxnb3JpdGhtcyI6IFsKICAgICAic2hhMjU2IiwKICAgICAic2hhNTEyIgogICAgXSwKICAgICJrZXl2YWwiOiB7CiAgICAgInB1YmxpYyI6ICJhNzliYWQ3MGE4OWJjNjQwODkzZThiMDM1ODQ4YmYyZTU2YWE4NWU1N2MwYzUwODVjNGEzZjVhNWMyZmUwNGYzIgogICAgfQogICB9CiAgfSwKICAicm9sZXMiOiB7CiAgICJyb290IjogewogICAgImtleWlkcyI6IFsKICAgICAiZThjNmIxZDIzMDc2ZjI5OGExMmM5MDhkOWE4NTdkMWRlZTcxMjc1ZDVkN2E2ZWU5NDZhMjMzZTgzMTBmMjc2YSIKICAgIF0sCiAgICAidGhyZXNob2xkIjogMQogICB9LAogICAic25hcHNob3QiOiB7CiAgICAia2V5aWRzIjogWwogICAgICJmNWYzMTMzYjcwMzljYTMzZjk2ZDI5OTMzN2Q1ZTQyNWVhNzk4MzIyMDEzNjY5OWJlODhhZjU2NWU5NmIyZWVhIgogICAgXSwKICAgICJ0aHJlc2hvbGQiOiAxCiAgIH0sCiAgICJ0YXJnZXRzIjogewogICAgImtleWlkcyI6IFsKICAgICAiOTE4MmI1ODVlNzFiOTVmMDA1YzIyZWNkYjQwN2QxMDY5YTlkMjdiOGMzZmFmMzBmMmUxZmM5NTRhNWFkOWNmNiIKICAgIF0sCiAgICAidGhyZXNob2xkIjogMQogICB9LAogICAidGltZXN0YW1wIjogewogICAgImtleWlkcyI6IFsKICAgICAiMGY4YzVmMzZmYjQzMDcxMjJmYjc5NzBlMjI0YjRlMDg2NGY0YWZhNGU0ZjYzNGJlNzc4OGU5ZWJkOWYyNjc4NSIKICAgIF0sCiAgICAidGhyZXNob2xkIjogMQogICB9CiAgfSwKICAiY29uc2lzdGVudF9zbmFwc2hvdCI6IHRydWUKIH0sCiAic2lnbmF0dXJlcyI6IFsKICB7CiAgICJrZXlpZCI6ICJlOGM2YjFkMjMwNzZmMjk4YTEyYzkwOGQ5YTg1N2QxZGVlNzEyNzVkNWQ3YTZlZTk0NmEyMzNlODMxMGYyNzZhIiwKICAgInNpZyI6ICI1MmM2YTkyNGFiZWYwMGY1YzY2NDE0OGIzMWRjMDRkOTVhNWE5ZjY1MjJlNTkwMDAyMzViNTAxNDUxYjRmYzc0MjEwZTVhY2NhOTRkZWIyZmNhNTgzZmM4ZTY4NDY0NTRiYTY2YzFhNzY4NWMxMDJhMDQ5N2JiMDNlMTEzYjIwMyIKICB9CiBdCn0=`
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
