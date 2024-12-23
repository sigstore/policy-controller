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

	// IMPORTANT: The next expiration is on '2025-06-20T10:07:23Z'
	rootJSON = `ewogInNpZ25lZCI6IHsKICAiX3R5cGUiOiAicm9vdCIsCiAgInNwZWNfdmVyc2lvbiI6ICIxLjAiLAogICJ2ZXJzaW9uIjogMSwKICAiZXhwaXJlcyI6ICIyMDI1LTA2LTIwVDEwOjA3OjIzWiIsCiAgImtleXMiOiB7CiAgICIxOGRhNDVlN2Y5ZmY5NTRiNzJmMTliNGViZDczNmU4OGI2NjhjMjNkZjRkZWM0ZTU4ZjZhMDM3MWFmOWJiMzY2IjogewogICAgImtleXR5cGUiOiAiZWQyNTUxOSIsCiAgICAic2NoZW1lIjogImVkMjU1MTkiLAogICAgImtleWlkX2hhc2hfYWxnb3JpdGhtcyI6IFsKICAgICAic2hhMjU2IiwKICAgICAic2hhNTEyIgogICAgXSwKICAgICJrZXl2YWwiOiB7CiAgICAgInB1YmxpYyI6ICI2OWIzOWRlOTY3NGRlYjc3N2VhNTgwMmYwMjU5MmUzYTg3YzRiZDNhMDEwZTRkMWM5OGU1M2FkMjdjOTBjNGI4IgogICAgfQogICB9LAogICAiNmUzMTk3M2RkMjU1ZGM5MWRjYTgwOGU0MzcxZjNlY2EyMjM2OTBkNjJhZWFmYmE0MmQxNGIwM2YzODYzOTMwOCI6IHsKICAgICJrZXl0eXBlIjogImVkMjU1MTkiLAogICAgInNjaGVtZSI6ICJlZDI1NTE5IiwKICAgICJrZXlpZF9oYXNoX2FsZ29yaXRobXMiOiBbCiAgICAgInNoYTI1NiIsCiAgICAgInNoYTUxMiIKICAgIF0sCiAgICAia2V5dmFsIjogewogICAgICJwdWJsaWMiOiAiYzc0NGVhODUzNjg5Yjg5YzYyZjBmMDZjYjgyOGE4OTVhYTQ3ODZlOTEzZWE3ZmE5Y2NhYzRkODgxZDcxYmJmZSIKICAgIH0KICAgfSwKICAgIjZlNWI3NzUzNmMwMjhjMWZiYzIwNGRjYjRlOTczMjZjZWRkNjY5YmZiNDVmOTlkYTdmYjRmMjYyNThhMDM5ODYiOiB7CiAgICAia2V5dHlwZSI6ICJlZDI1NTE5IiwKICAgICJzY2hlbWUiOiAiZWQyNTUxOSIsCiAgICAia2V5aWRfaGFzaF9hbGdvcml0aG1zIjogWwogICAgICJzaGEyNTYiLAogICAgICJzaGE1MTIiCiAgICBdLAogICAgImtleXZhbCI6IHsKICAgICAicHVibGljIjogImU0ODA1NGYxYzhmYzQzNDUxY2E2NmU4ZmE1MjQ4NzA5YzYyYThmZjM5ZGU4ZjliYjIxZGRiOGM2YTM3YzcyZWQiCiAgICB9CiAgIH0sCiAgICJkNmY0MTc0Zjk1YjM3YWEyYTBmOGIxZWM1NGRmOWQwY2NmZWQ4MjQzMzEyZDE5ZjIxYWM1OWFkNTAxYmM2YTZiIjogewogICAgImtleXR5cGUiOiAiZWQyNTUxOSIsCiAgICAic2NoZW1lIjogImVkMjU1MTkiLAogICAgImtleWlkX2hhc2hfYWxnb3JpdGhtcyI6IFsKICAgICAic2hhMjU2IiwKICAgICAic2hhNTEyIgogICAgXSwKICAgICJrZXl2YWwiOiB7CiAgICAgInB1YmxpYyI6ICIwY2I5MzFjNTAzY2EzYjBjNjRjN2E3Mzc3Mzc3YWYzYTgwMjA2ZTk2Yzc5NGY4NTA5NzkzOTk0YTE5MGEzYzMzIgogICAgfQogICB9CiAgfSwKICAicm9sZXMiOiB7CiAgICJyb290IjogewogICAgImtleWlkcyI6IFsKICAgICAiNmU1Yjc3NTM2YzAyOGMxZmJjMjA0ZGNiNGU5NzMyNmNlZGQ2NjliZmI0NWY5OWRhN2ZiNGYyNjI1OGEwMzk4NiIKICAgIF0sCiAgICAidGhyZXNob2xkIjogMQogICB9LAogICAic25hcHNob3QiOiB7CiAgICAia2V5aWRzIjogWwogICAgICJkNmY0MTc0Zjk1YjM3YWEyYTBmOGIxZWM1NGRmOWQwY2NmZWQ4MjQzMzEyZDE5ZjIxYWM1OWFkNTAxYmM2YTZiIgogICAgXSwKICAgICJ0aHJlc2hvbGQiOiAxCiAgIH0sCiAgICJ0YXJnZXRzIjogewogICAgImtleWlkcyI6IFsKICAgICAiMThkYTQ1ZTdmOWZmOTU0YjcyZjE5YjRlYmQ3MzZlODhiNjY4YzIzZGY0ZGVjNGU1OGY2YTAzNzFhZjliYjM2NiIKICAgIF0sCiAgICAidGhyZXNob2xkIjogMQogICB9LAogICAidGltZXN0YW1wIjogewogICAgImtleWlkcyI6IFsKICAgICAiNmUzMTk3M2RkMjU1ZGM5MWRjYTgwOGU0MzcxZjNlY2EyMjM2OTBkNjJhZWFmYmE0MmQxNGIwM2YzODYzOTMwOCIKICAgIF0sCiAgICAidGhyZXNob2xkIjogMQogICB9CiAgfSwKICAiY29uc2lzdGVudF9zbmFwc2hvdCI6IHRydWUKIH0sCiAic2lnbmF0dXJlcyI6IFsKICB7CiAgICJrZXlpZCI6ICI2ZTViNzc1MzZjMDI4YzFmYmMyMDRkY2I0ZTk3MzI2Y2VkZDY2OWJmYjQ1Zjk5ZGE3ZmI0ZjI2MjU4YTAzOTg2IiwKICAgInNpZyI6ICJmM2IyMjMwNTk2ZmUzZTU1MzA2OTJmMGY4NGQxMjIxZjQ2YzhhMGRmODQzMGI5OTVjMjZkMjFkYzI3YTY5YTM5ZmQwNWE1MjMzMDBjNTE5ZWVhYzAzNmFkZDNlYmZkOTM3YmY3MjM1ZTcwNjU5YWMyMDgyYzhlYzQ4NTI5ZmYwMCIKICB9CiBdCn0=`
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
