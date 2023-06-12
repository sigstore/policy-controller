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

	// IMPORTANT: The next expiration is on '2023-12-12T08:58:28Z'
	rootJSON = `ewogInNpZ25lZCI6IHsKICAiX3R5cGUiOiAicm9vdCIsCiAgInNwZWNfdmVyc2lvbiI6ICIxLjAiLAogICJ2ZXJzaW9uIjogMSwKICAiZXhwaXJlcyI6ICIyMDIzLTEyLTEyVDA4OjU4OjI4WiIsCiAgImtleXMiOiB7CiAgICI0OGZiNzRkODYyMThiZTM2MWM0NDJiNDZkOWQxZmEyOGM4ZjlmZTYzMjBmMzFkNWIyM2YxNGU1MDhmMzE4ZjZjIjogewogICAgImtleXR5cGUiOiAiZWQyNTUxOSIsCiAgICAic2NoZW1lIjogImVkMjU1MTkiLAogICAgImtleWlkX2hhc2hfYWxnb3JpdGhtcyI6IFsKICAgICAic2hhMjU2IiwKICAgICAic2hhNTEyIgogICAgXSwKICAgICJrZXl2YWwiOiB7CiAgICAgInB1YmxpYyI6ICJhZWZmZjY5YTg3MDRiOGU4NWI0YzI4ODljY2QwYzBjYTdkM2FhYTZiYjlkMDEyNDY3MDkzYzQ0YjBhYWZiMDI0IgogICAgfQogICB9LAogICAiYjIyNGJkNzNkYjcxMmFiNzk2MjJhZDU5YjY0ZTk4ZGU2YjUzM2ViZTlhYWQ2NTUyZTc3NjkxNzkxMWViNmVmMSI6IHsKICAgICJrZXl0eXBlIjogImVkMjU1MTkiLAogICAgInNjaGVtZSI6ICJlZDI1NTE5IiwKICAgICJrZXlpZF9oYXNoX2FsZ29yaXRobXMiOiBbCiAgICAgInNoYTI1NiIsCiAgICAgInNoYTUxMiIKICAgIF0sCiAgICAia2V5dmFsIjogewogICAgICJwdWJsaWMiOiAiNGM2ZTNhZjFjNTEzZWM1NzhmZDk1MGIyODlhNmFiMzJlOGZkMmFjZGQ0ZGYzNjYxMDIwOTA5NGYxNjE4M2ZhNCIKICAgIH0KICAgfSwKICAgImQxNmZhYzQ1YjQ3ZTNlMjMxNzIxZDQ0NTQxYjJmMWY5OTk5YWZmODQxZTRlZTYzYTkwOGQ3NDcxYjI4MTFiODkiOiB7CiAgICAia2V5dHlwZSI6ICJlZDI1NTE5IiwKICAgICJzY2hlbWUiOiAiZWQyNTUxOSIsCiAgICAia2V5aWRfaGFzaF9hbGdvcml0aG1zIjogWwogICAgICJzaGEyNTYiLAogICAgICJzaGE1MTIiCiAgICBdLAogICAgImtleXZhbCI6IHsKICAgICAicHVibGljIjogIjM1NjdjOTk1ZDBkZWI4NzAyYzA2NTFkYTU1OTE3NzU3YzNlZjI5ZGQ0MmNlNGQ5ZmY5MzU3YTMxNWFmMzM2NzMiCiAgICB9CiAgIH0sCiAgICJkOGFhOTdkNDk5ODk1MzNkMDE2NmE0YjRhMjdmYmU4YzVjMTRiOThiYjVkMDI1NThiODUwN2RiZDNmNTA5ZWU2IjogewogICAgImtleXR5cGUiOiAiZWQyNTUxOSIsCiAgICAic2NoZW1lIjogImVkMjU1MTkiLAogICAgImtleWlkX2hhc2hfYWxnb3JpdGhtcyI6IFsKICAgICAic2hhMjU2IiwKICAgICAic2hhNTEyIgogICAgXSwKICAgICJrZXl2YWwiOiB7CiAgICAgInB1YmxpYyI6ICJlNjg5NDkyM2EyY2M5MDA1MzU3OTA4NGQxNWIzMWFlNDBlNjBhMDRhODdiNzYxZjEzN2ZkMzRlOTY4MDAzNzNkIgogICAgfQogICB9CiAgfSwKICAicm9sZXMiOiB7CiAgICJyb290IjogewogICAgImtleWlkcyI6IFsKICAgICAiZDE2ZmFjNDViNDdlM2UyMzE3MjFkNDQ1NDFiMmYxZjk5OTlhZmY4NDFlNGVlNjNhOTA4ZDc0NzFiMjgxMWI4OSIKICAgIF0sCiAgICAidGhyZXNob2xkIjogMQogICB9LAogICAic25hcHNob3QiOiB7CiAgICAia2V5aWRzIjogWwogICAgICJkOGFhOTdkNDk5ODk1MzNkMDE2NmE0YjRhMjdmYmU4YzVjMTRiOThiYjVkMDI1NThiODUwN2RiZDNmNTA5ZWU2IgogICAgXSwKICAgICJ0aHJlc2hvbGQiOiAxCiAgIH0sCiAgICJ0YXJnZXRzIjogewogICAgImtleWlkcyI6IFsKICAgICAiYjIyNGJkNzNkYjcxMmFiNzk2MjJhZDU5YjY0ZTk4ZGU2YjUzM2ViZTlhYWQ2NTUyZTc3NjkxNzkxMWViNmVmMSIKICAgIF0sCiAgICAidGhyZXNob2xkIjogMQogICB9LAogICAidGltZXN0YW1wIjogewogICAgImtleWlkcyI6IFsKICAgICAiNDhmYjc0ZDg2MjE4YmUzNjFjNDQyYjQ2ZDlkMWZhMjhjOGY5ZmU2MzIwZjMxZDViMjNmMTRlNTA4ZjMxOGY2YyIKICAgIF0sCiAgICAidGhyZXNob2xkIjogMQogICB9CiAgfSwKICAiY29uc2lzdGVudF9zbmFwc2hvdCI6IGZhbHNlCiB9LAogInNpZ25hdHVyZXMiOiBbCiAgewogICAia2V5aWQiOiAiZDE2ZmFjNDViNDdlM2UyMzE3MjFkNDQ1NDFiMmYxZjk5OTlhZmY4NDFlNGVlNjNhOTA4ZDc0NzFiMjgxMWI4OSIsCiAgICJzaWciOiAiNjBmMzI2ZDg3OGE1MzliMDc1NDVjNDZmMDI2Y2IxZDE0NTIxNWRhOWIzNmM1NzNjMWIzNGFlOGI3NGNlYWZiYjM1NDlmOTVmMjgyYjJmZjVhZmFiMjhmMTJjYWM2OTE0MDRjYzg5YmYwOTUyMWY2ODdiZmRkMzZmM2JkZjZlMDkiCiAgfQogXQp9`
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
	if err := os.WriteFile(path, data, 0644); err != nil {
		return err
	}
	return nil
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
