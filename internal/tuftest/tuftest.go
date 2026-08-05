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

// Package tuftest builds throwaway TUF repositories for use in tests.
//
// TUF metadata expires, so committing pre-built repositories to the tree means
// the test suite breaks purely with the passage of time. Tests should call
// NewRepo or NewRepoDir instead, which sign fresh metadata on every run with an
// expiry relative to "now".
//
// This package deliberately does not import
// github.com/sigstore/policy-controller/pkg/tuf: pkg/tuf's own tests are
// in-package (`package tuf`), so such an import would form an import cycle.
package tuftest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sigstore/scaffolding/pkg/repo"
	"github.com/theupdateframework/go-tuf"
)

// DefaultValidity is how far in the future generated metadata expires. It
// matches the six months used by sigstore/scaffolding, but because it is always
// applied relative to time.Now() the resulting repository never goes stale.
const DefaultValidity = 6 * 30 * 24 * time.Hour

// roles are the top-level TUF roles that get a generated signing key.
var roles = []string{"root", "targets", "snapshot", "timestamp"}

// Target is a file to publish in the generated repository.
type Target struct {
	// Name is the target path within the repository, e.g. "rekor.pem". The
	// name is significant: sigstore derives a target's usage from it, so
	// callers should keep using the same filenames as production repositories.
	Name string

	// Bytes is the target's content.
	Bytes []byte

	// CustomMetadata is the target's TUF custom metadata. When nil, sigstore
	// custom metadata is generated from Name, matching what
	// scaffolding's repo.CreateRepoWithOptions would have produced.
	CustomMetadata []byte
}

type config struct {
	expires            time.Time
	consistentSnapshot bool
	addCustomMetadata  bool
}

// Option configures repository generation.
type Option func(*config)

// WithExpires sets the expiry stamped into every generated metadata file. It
// must be in the future: go-tuf refuses to sign metadata that has already
// expired. To exercise expiry handling, set a short validity and wait for it to
// lapse, reading the effective expiry back out of the generated metadata, since
// go-tuf rounds to the nearest second.
func WithExpires(t time.Time) Option {
	return func(c *config) { c.expires = t }
}

// WithConsistentSnapshot controls the TUF consistent snapshot setting. It
// defaults to true, matching sigstore/scaffolding and therefore production
// sigstore TUF repositories.
func WithConsistentSnapshot(b bool) Option {
	return func(c *config) { c.consistentSnapshot = b }
}

// WithSigstoreCustomMetadata controls whether targets without explicit
// CustomMetadata get sigstore usage metadata generated from their name. It
// defaults to true.
func WithSigstoreCustomMetadata(b bool) Option {
	return func(c *config) { c.addCustomMetadata = b }
}

// customMetadata mirrors the shape scaffolding writes for each target.
type customMetadata struct {
	Sigstore struct {
		Usage  string `json:"usage"`
		Status string `json:"status"`
		URI    string `json:"uri"`
	} `json:"sigstore"`
}

// targetUsage reproduces scaffolding's filename-based usage derivation.
func targetUsage(name string) string {
	for _, known := range []string{repo.FulcioTarget, repo.RekorTarget, repo.CTFETarget, repo.TSATarget} {
		if strings.Contains(strings.ToLower(name), strings.ToLower(known)) {
			return known
		}
	}
	return repo.UnknownTarget
}

func sigstoreMetadata(name string) ([]byte, error) {
	var cm customMetadata
	cm.Sigstore.Usage = targetUsage(name)
	cm.Sigstore.Status = "Active"
	return json.Marshal(&cm)
}

// NewRepoDir creates and commits a TUF repository containing targets in a
// temporary directory scoped to t, and returns the backing store along with the
// repository's root directory. The directory contains the usual "repository",
// "staged" and "keys" subdirectories.
//
// Unlike scaffolding's repo.CreateRepoWithMetadata, which always writes to a
// single fixed path under os.TempDir, this is safe to call repeatedly and from
// tests running in parallel.
func NewRepoDir(t *testing.T, targets []Target, opts ...Option) (tuf.LocalStore, string) {
	t.Helper()

	cfg := config{
		expires:            time.Now().Add(DefaultValidity),
		consistentSnapshot: true,
		addCustomMetadata:  true,
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	dir := t.TempDir()
	local := tuf.FileSystemStore(dir, nil)

	r, err := tuf.NewRepoIndent(local, "", " ")
	if err != nil {
		t.Fatalf("tuftest: NewRepoIndent: %v", err)
	}
	if err := r.Init(cfg.consistentSnapshot); err != nil {
		t.Fatalf("tuftest: Init: %v", err)
	}

	for _, role := range roles {
		if _, err := r.GenKeyWithExpires(role, cfg.expires); err != nil {
			t.Fatalf("tuftest: GenKeyWithExpires(%s): %v", role, err)
		}
	}

	for _, target := range targets {
		if err := writeStagedTarget(dir, target.Name, target.Bytes); err != nil {
			t.Fatalf("tuftest: staging target %s: %v", target.Name, err)
		}
		meta := target.CustomMetadata
		if meta == nil && cfg.addCustomMetadata {
			if meta, err = sigstoreMetadata(target.Name); err != nil {
				t.Fatalf("tuftest: custom metadata for %s: %v", target.Name, err)
			}
		}
		if err := r.AddTargetWithExpires(target.Name, meta, cfg.expires); err != nil {
			t.Fatalf("tuftest: AddTargetWithExpires(%s): %v", target.Name, err)
		}
	}

	if err := r.SnapshotWithExpires(cfg.expires); err != nil {
		t.Fatalf("tuftest: SnapshotWithExpires: %v", err)
	}
	if err := r.TimestampWithExpires(cfg.expires); err != nil {
		t.Fatalf("tuftest: TimestampWithExpires: %v", err)
	}
	if err := r.Commit(); err != nil {
		t.Fatalf("tuftest: Commit: %v", err)
	}

	return local, dir
}

// NewRepo creates a TUF repository containing targets and returns it serialized
// as a gzipped tarball, along with its root.json. The tarball is rooted at
// "repository/" and excludes private key material, so it is suitable for a
// TrustRoot's mirrorFS.
//
// Callers testing this repository's own compression helpers should use
// NewRepoDir and compress the directory themselves, so that the code under test
// is the code actually exercised.
func NewRepo(t *testing.T, targets []Target, opts ...Option) (tarGz, rootJSON []byte) {
	t.Helper()

	local, dir := NewRepoDir(t, targets, opts...)

	meta, err := local.GetMeta()
	if err != nil {
		t.Fatalf("tuftest: GetMeta: %v", err)
	}
	rootJSON, ok := meta["root.json"]
	if !ok {
		t.Fatal("tuftest: generated repository has no root.json")
	}

	return Compress(t, dir), rootJSON
}

// Compress archives a repository directory produced by NewRepoDir, skipping the
// private keys and staging areas.
func Compress(t *testing.T, dir string) []byte {
	t.Helper()

	var buf bytes.Buffer
	if err := repo.CompressFS(os.DirFS(dir), &buf, map[string]bool{"keys": true, "staged": true}); err != nil {
		t.Fatalf("tuftest: CompressFS: %v", err)
	}
	return buf.Bytes()
}

func writeStagedTarget(dir, name string, data []byte) error {
	path := filepath.Join(dir, "staged", "targets", name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("creating staged target dir: %w", err)
	}
	/* #nosec G306 */
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("writing staged target: %w", err)
	}
	return nil
}
