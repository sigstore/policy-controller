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
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"
	"time"

	"github.com/sigstore/policy-controller/internal/tuftest"
	"github.com/theupdateframework/go-tuf/v2/metadata"
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
)

// testTargets are the targets used by the tests in this file. The names match
// the ones a real sigstore TUF repository publishes.
func testTargets() []tuftest.Target {
	return []tuftest.Target{
		{Name: "fulcio_v1.crt.pem", Bytes: []byte(fulcioRootCert)},
		{Name: "ctfe.pub", Bytes: []byte(ctlogPublicKey)},
		{Name: "rekor.pub", Bytes: []byte(rekorPublicKey)},
	}
}

func TestCompressUncompressFS(t *testing.T) {
	targets := testTargets()
	// Generate into a directory rather than asking the helper for a tarball, so
	// that the compression exercised below is this package's own.
	local, dir := tuftest.NewRepoDir(t, targets, tuftest.WithConsistentSnapshot(false))

	var buf bytes.Buffer
	fsys := os.DirFS(dir)
	if err := CompressFS(fsys, &buf, map[string]bool{"keys": true, "staged": true}); err != nil {
		t.Fatalf("Failed to compress: %v", err)
	}
	dstDir := t.TempDir()
	if err := Uncompress(&buf, dstDir); err != nil {
		t.Fatalf("Failed to uncompress: %v", err)
	}
	// Then check that files have been uncompressed there.
	meta, err := local.GetMeta()
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
	if !bytes.Equal([]byte(rekorPublicKey), rtRekor) {
		t.Errorf("Roundtripped rekor differs:\n%s\n%s", rekorPublicKey, string(rtRekor))
	}
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
	repo, root := tuftest.NewRepo(t, testTargets())
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
	repo, root := tuftest.NewRepo(t, testTargets())
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

// TestClientFromSerializedMirrorExpired guards against the fixtures above being
// made "fresh" by accidentally disabling expiry validation: a repository whose
// metadata has expired must still be rejected. go-tuf refuses to sign metadata
// that is already expired, so this signs a short-lived repository and waits for
// it to lapse.
func TestClientFromSerializedMirrorExpired(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping expiry test in short mode")
	}

	repo, root := tuftest.NewRepo(t, testTargets(), tuftest.WithExpires(time.Now().Add(2*time.Second)))

	// Wait on the expiry recorded in the metadata rather than the one requested:
	// go-tuf rounds to the nearest second, so the effective expiry can be up to
	// half a second later than asked for.
	var doc struct {
		Signed struct {
			Expires time.Time `json:"expires"`
		} `json:"signed"`
	}
	if err := json.Unmarshal(root, &doc); err != nil {
		t.Fatalf("failed to read the generated root.json: %v", err)
	}
	time.Sleep(time.Until(doc.Signed.Expires) + 100*time.Millisecond)

	tufClient, err := ClientFromSerializedMirror(context.Background(), repo, root, "targets", "/repository/")
	if err != nil {
		// Rejected eagerly, which is fine.
		return
	}
	if _, err := tufClient.GetTopLevelTargets(); err == nil {
		t.Error("expected expired TUF metadata to be rejected, got no error")
	}
}

func TestClientFromRemoteMirror(t *testing.T) {
	local, dir := tuftest.NewRepoDir(t, testTargets(), tuftest.WithConsistentSnapshot(false))
	meta, err := local.GetMeta()
	if err != nil {
		t.Fatalf("getting meta: %v", err)
	}
	rootJSON, ok := meta["root.json"]
	if !ok {
		t.Fatal("generated repository has no root.json")
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
