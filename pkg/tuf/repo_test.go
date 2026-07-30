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
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"
	"time"

	"github.com/theupdateframework/go-tuf"
	"github.com/theupdateframework/go-tuf/v2/metadata"
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

	// IMPORTANT: The next expiration is on '2027-01-28T17:36:23Z'
	// To regenerate rootJSON and the matching validRepository above, run
	// `make generate-testdata` and base64-encode the resulting
	// pkg/reconciler/trustroot/testdata/root.json and tufRepo.tar respectively.
	rootJSON = `ewogInNpZ25lZCI6IHsKICAiX3R5cGUiOiAicm9vdCIsCiAgInNwZWNfdmVyc2lvbiI6ICIxLjAiLAogICJ2ZXJzaW9uIjogMSwKICAiZXhwaXJlcyI6ICIyMDI3LTAxLTI4VDE3OjM2OjIzWiIsCiAgImtleXMiOiB7CiAgICIzZDk1NWRlZTk5ODMwYmUwNTc1MWQyMmNjMDUwYTQ3NWI2OTIwZGUyZDM2MWNiZGVhNjJmYzE0YTY2MTg3MzU5IjogewogICAgImtleXR5cGUiOiAiZWQyNTUxOSIsCiAgICAic2NoZW1lIjogImVkMjU1MTkiLAogICAgImtleWlkX2hhc2hfYWxnb3JpdGhtcyI6IFsKICAgICAic2hhMjU2IiwKICAgICAic2hhNTEyIgogICAgXSwKICAgICJrZXl2YWwiOiB7CiAgICAgInB1YmxpYyI6ICIwOWI2MjM5ZTkyNTBjMWEzODIyY2UwY2YzZmMxMjdiMjY3YmUwZTUyYWZlYjA0YWY4MDQ2MmM0ZmM2MWE4NDI0IgogICAgfQogICB9LAogICAiNTU0NjRhMzRhMzk1NWQ3NTMxMzE0M2Y0ZThmZGE0NzRlNWRkMmYwNjcwYTc5ZGE0ZDIzZDhiMWNkZDQ3ZDNlMiI6IHsKICAgICJrZXl0eXBlIjogImVkMjU1MTkiLAogICAgInNjaGVtZSI6ICJlZDI1NTE5IiwKICAgICJrZXlpZF9oYXNoX2FsZ29yaXRobXMiOiBbCiAgICAgInNoYTI1NiIsCiAgICAgInNoYTUxMiIKICAgIF0sCiAgICAia2V5dmFsIjogewogICAgICJwdWJsaWMiOiAiYjIyYzQ3NDM5ZGIxNDk5MDhlY2ZhOTA0MDZhZDA5MzJjMzNkOTkwOThhODQ3MWY1ZmU3MjMwZjRkZjRjZmJkZSIKICAgIH0KICAgfSwKICAgIjZjMDc5MzVkY2RjZDRjNmM4NmUxZGM3OTc1NmY2MTY5MDZkZDhhNWQ1YWRjN2NlN2NlMzg1YTllYTIyMTlmMGEiOiB7CiAgICAia2V5dHlwZSI6ICJlZDI1NTE5IiwKICAgICJzY2hlbWUiOiAiZWQyNTUxOSIsCiAgICAia2V5aWRfaGFzaF9hbGdvcml0aG1zIjogWwogICAgICJzaGEyNTYiLAogICAgICJzaGE1MTIiCiAgICBdLAogICAgImtleXZhbCI6IHsKICAgICAicHVibGljIjogImZkNWM1YzhkNmU2MTFkNTdkYWIxYzk0YjEyODVkMmE1NWI3OWQ5MTg3MGY0ZjBhZjg1ZDRiMTkyZmRlYjdkMjUiCiAgICB9CiAgIH0sCiAgICJmMDBlMTU3YTc1OGU3ZGZlMmY3OTc0N2RmNzgwNjM4MmFmNzBhODc0YmIzZTJjZTc2MmJhOThkOWQ4NGU5YWRmIjogewogICAgImtleXR5cGUiOiAiZWQyNTUxOSIsCiAgICAic2NoZW1lIjogImVkMjU1MTkiLAogICAgImtleWlkX2hhc2hfYWxnb3JpdGhtcyI6IFsKICAgICAic2hhMjU2IiwKICAgICAic2hhNTEyIgogICAgXSwKICAgICJrZXl2YWwiOiB7CiAgICAgInB1YmxpYyI6ICI5MmU0NGFmNTgyNzU4NjQ1ODVmYzVlMjI2NmRjMDdkZWFjNzFiY2RmN2Q3YzVkYWI2NWQ2MTYxY2E1MDAxN2JiIgogICAgfQogICB9CiAgfSwKICAicm9sZXMiOiB7CiAgICJyb290IjogewogICAgImtleWlkcyI6IFsKICAgICAiNTU0NjRhMzRhMzk1NWQ3NTMxMzE0M2Y0ZThmZGE0NzRlNWRkMmYwNjcwYTc5ZGE0ZDIzZDhiMWNkZDQ3ZDNlMiIKICAgIF0sCiAgICAidGhyZXNob2xkIjogMQogICB9LAogICAic25hcHNob3QiOiB7CiAgICAia2V5aWRzIjogWwogICAgICIzZDk1NWRlZTk5ODMwYmUwNTc1MWQyMmNjMDUwYTQ3NWI2OTIwZGUyZDM2MWNiZGVhNjJmYzE0YTY2MTg3MzU5IgogICAgXSwKICAgICJ0aHJlc2hvbGQiOiAxCiAgIH0sCiAgICJ0YXJnZXRzIjogewogICAgImtleWlkcyI6IFsKICAgICAiNmMwNzkzNWRjZGNkNGM2Yzg2ZTFkYzc5NzU2ZjYxNjkwNmRkOGE1ZDVhZGM3Y2U3Y2UzODVhOWVhMjIxOWYwYSIKICAgIF0sCiAgICAidGhyZXNob2xkIjogMQogICB9LAogICAidGltZXN0YW1wIjogewogICAgImtleWlkcyI6IFsKICAgICAiZjAwZTE1N2E3NThlN2RmZTJmNzk3NDdkZjc4MDYzODJhZjcwYTg3NGJiM2UyY2U3NjJiYTk4ZDlkODRlOWFkZiIKICAgIF0sCiAgICAidGhyZXNob2xkIjogMQogICB9CiAgfSwKICAiY29uc2lzdGVudF9zbmFwc2hvdCI6IHRydWUKIH0sCiAic2lnbmF0dXJlcyI6IFsKICB7CiAgICJrZXlpZCI6ICI1NTQ2NGEzNGEzOTU1ZDc1MzEzMTQzZjRlOGZkYTQ3NGU1ZGQyZjA2NzBhNzlkYTRkMjNkOGIxY2RkNDdkM2UyIiwKICAgInNpZyI6ICJjNDg2MDhlYTRjMzY3N2QyNTE5OTQyMWJiYTM5YTE3NTM5YjRmOGUyMzU4MWEzMWQ3YjY2NDIyNTAxOGYxNmRjOTE1OTgyNjM2YjlhMDMxODc2ZjAyYzY5YmQxMTFjZTA4YTg0ZWQzODY5YjI0ZDZhNDg0YTY1YjJmZmE2Y2IwOSIKICB9CiBdCn0=`
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

func TestFsFetcherNotFound(t *testing.T) {
	testFS := fstest.MapFS{
		"existing.json": &fstest.MapFile{Data: []byte(`{"hello":"world"}`)},
	}
	f := &fsFetcher{fsys: testFS, baseURL: "mem://test/"}

	// Existing file should succeed
	data, err := f.DownloadFile("mem://test/existing.json", 0, 0)
	if err != nil {
		t.Fatalf("unexpected error for existing file: %v", err)
	}
	if string(data) != `{"hello":"world"}` {
		t.Errorf("unexpected data: %s", data)
	}

	// Missing file should return ErrDownloadHTTP with 404
	_, err = f.DownloadFile("mem://test/missing.json", 0, 0)
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	var httpErr *metadata.ErrDownloadHTTP
	if !errors.As(err, &httpErr) || httpErr.StatusCode != 404 {
		t.Errorf("expected ErrDownloadHTTP{404}, got: %v", err)
	}
}

func TestFsFetcherMaxLength(t *testing.T) {
	testFS := fstest.MapFS{
		"big.json": &fstest.MapFile{Data: make([]byte, 100)},
	}
	f := &fsFetcher{fsys: testFS, baseURL: "mem://test/"}

	// Should succeed when maxLength is 0 (unlimited)
	_, err := f.DownloadFile("mem://test/big.json", 0, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should fail when file exceeds maxLength
	_, err = f.DownloadFile("mem://test/big.json", 50, 0)
	if err == nil {
		t.Fatal("expected error for oversized file")
	}
	var lenErr *metadata.ErrDownloadLengthMismatch
	if !errors.As(err, &lenErr) {
		t.Errorf("expected ErrDownloadLengthMismatch, got: %v", err)
	}
}

func TestDownloadTargetFromSerializedMirror(t *testing.T) {
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
		t.Fatalf("Failed to create client: %v", err)
	}

	// Download each target via GetTarget and verify it has content
	targets, err := tufClient.GetTopLevelTargets()
	if err != nil {
		t.Fatalf("GetTopLevelTargets error: %v", err)
	}
	for name := range targets {
		data, err := tufClient.GetTarget(name)
		if err != nil {
			t.Errorf("GetTarget(%s) error: %v", name, err)
			continue
		}
		if len(data) == 0 {
			t.Errorf("GetTarget(%s) returned empty data", name)
		}
	}
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
	targets, err := tufClient.GetTopLevelTargets()
	if err != nil {
		t.Fatalf("GetTopLevelTargets error: %v", err)
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
	targets, err := tufClient.GetTopLevelTargets()
	if err != nil {
		t.Fatalf("GetTopLevelTargets error: %v", err)
	}
	if len(targets) == 0 {
		t.Errorf("Got no targets from the TUF client")
	}
}
