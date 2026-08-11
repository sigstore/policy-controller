// Copyright 2026 The Sigstore Authors.
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

package tuftest

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func testTargets() []Target {
	return []Target{
		{Name: "rekor.pem", Bytes: []byte("rekor")},
		{Name: "fulcio.pem", Bytes: []byte("fulcio")},
	}
}

// TestExpiryIsRelativeToNow is the point of this package: the generated
// metadata must expire relative to the current time, never on a fixed date.
func TestExpiryIsRelativeToNow(t *testing.T) {
	_, rootJSON := NewRepo(t, testTargets())

	var doc struct {
		Signed struct {
			Expires time.Time `json:"expires"`
		} `json:"signed"`
	}
	if err := json.Unmarshal(rootJSON, &doc); err != nil {
		t.Fatalf("unmarshalling root.json: %v", err)
	}

	want := time.Now().Add(DefaultValidity)
	if diff := doc.Signed.Expires.Sub(want); diff > time.Hour || diff < -time.Hour {
		t.Errorf("root.json expires at %s, want approximately %s (off by %s); "+
			"an expiry that is not relative to now will rot",
			doc.Signed.Expires, want, diff)
	}
}

func TestWithExpires(t *testing.T) {
	want := time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second)
	_, rootJSON := NewRepo(t, testTargets(), WithExpires(want))

	var doc struct {
		Signed struct {
			Expires time.Time `json:"expires"`
		} `json:"signed"`
	}
	if err := json.Unmarshal(rootJSON, &doc); err != nil {
		t.Fatalf("unmarshalling root.json: %v", err)
	}
	if !doc.Signed.Expires.Equal(want) {
		t.Errorf("root.json expires at %s, want %s", doc.Signed.Expires, want)
	}
}

// TestArchiveExcludesPrivateKeys makes sure the tarball handed to tests, which
// stands in for a TrustRoot's mirrorFS, never carries signing keys.
func TestArchiveExcludesPrivateKeys(t *testing.T) {
	tarGz, _ := NewRepo(t, testTargets())

	names := archiveNames(t, tarGz)
	if len(names) == 0 {
		t.Fatal("archive is empty")
	}
	for _, name := range names {
		if strings.HasPrefix(name, "keys/") || strings.HasPrefix(name, "staged/") {
			t.Errorf("archive contains %q, which may hold private key material", name)
		}
		if name != "repository" && !strings.HasPrefix(name, "repository/") {
			t.Errorf("archive entry %q is not under repository/", name)
		}
	}
}

func TestConsistentSnapshot(t *testing.T) {
	for _, consistent := range []bool{true, false} {
		t.Run(map[bool]string{true: "enabled", false: "disabled"}[consistent], func(t *testing.T) {
			_, rootJSON := NewRepo(t, testTargets(), WithConsistentSnapshot(consistent))

			var doc struct {
				Signed struct {
					ConsistentSnapshot bool `json:"consistent_snapshot"`
				} `json:"signed"`
			}
			if err := json.Unmarshal(rootJSON, &doc); err != nil {
				t.Fatalf("unmarshalling root.json: %v", err)
			}
			if doc.Signed.ConsistentSnapshot != consistent {
				t.Errorf("consistent_snapshot = %v, want %v", doc.Signed.ConsistentSnapshot, consistent)
			}
		})
	}
}

// TestSigstoreCustomMetadata covers the usage values the trustroot reconciler
// reads back out of each target's custom metadata.
func TestSigstoreCustomMetadata(t *testing.T) {
	for name, want := range map[string]string{
		"rekor.pem":     "Rekor",
		"fulcio.pem":    "Fulcio",
		"ctfe.pem":      "CTFE",
		"tsa_leaf.pem":  "TSA",
		"something.pem": "Unknown",
	} {
		if got := targetUsage(name); got != want {
			t.Errorf("targetUsage(%q) = %q, want %q", name, got, want)
		}
	}
}

// TestNewRepoDirIsIsolated covers the collision that the old fixed /tmp/tuf
// path caused: generating two repositories in one test must just work.
func TestNewRepoDirIsIsolated(t *testing.T) {
	_, first := NewRepoDir(t, testTargets())
	_, second := NewRepoDir(t, testTargets())
	if first == second {
		t.Errorf("both repositories were created in %s", first)
	}
}

func archiveNames(t *testing.T, tarGz []byte) []string {
	t.Helper()

	zr, err := gzip.NewReader(bytes.NewReader(tarGz))
	if err != nil {
		t.Fatalf("opening gzip stream: %v", err)
	}
	defer zr.Close()

	var names []string
	tr := tar.NewReader(zr)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return names
		}
		if err != nil {
			t.Fatalf("reading archive: %v", err)
		}
		names = append(names, hdr.Name)
	}
}
