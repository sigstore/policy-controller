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
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// skipDirs are directories that are not ours to police.
var skipDirs = map[string]bool{
	".git":         true,
	"vendor":       true,
	"third_party":  true,
	"node_modules": true,
}

const guidance = `Committed TUF metadata expires, which breaks CI purely with the passage of
time (see https://github.com/sigstore/policy-controller/issues/2001). Generate
repositories at test time with internal/tuftest instead of committing them.`

// TestNoCommittedTUFMetadata fails if TUF metadata is committed anywhere in the
// tree. This is a guardrail rather than a test of behaviour: it exists so that
// a pre-built, and therefore expiring, TUF repository cannot quietly reappear.
//
// It covers the three shapes these fixtures have historically taken: metadata
// files, tarred repositories, and base64-encoded repositories inlined into Go
// source.
func TestNoCommittedTUFMetadata(t *testing.T) {
	root := repoRoot(t)

	var found []string
	for _, rel := range committedFiles(t, root) {
		path := filepath.Join(root, rel)
		if reason := inspect(path); reason != "" {
			found = append(found, rel+" ("+reason+")")
		}
	}

	if len(found) > 0 {
		t.Errorf("found committed TUF metadata:\n\t%s\n\n%s", strings.Join(found, "\n\t"), guidance)
	}
}

// inspect returns a description of the TUF metadata in path, or the empty
// string if there is none.
func inspect(path string) string {
	switch {
	case strings.HasSuffix(path, ".json"):
		if expires := tufExpiry(mustRead(path)); expires != "" {
			return "TUF metadata expiring " + expires
		}
	case strings.HasSuffix(path, ".tar"), strings.HasSuffix(path, ".tar.gz"), strings.HasSuffix(path, ".tgz"):
		if archiveHasTUFMetadata(mustRead(path)) {
			return "archive containing a TUF repository"
		}
	case strings.HasSuffix(path, ".go"):
		if reason := inlinedTUFMetadata(mustRead(path)); reason != "" {
			return reason
		}
	}
	return ""
}

func mustRead(path string) []byte {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return b
}

// base64Literal matches the long base64 string literals these fixtures were
// historically stored in. The lower bound keeps ordinary
// constants out; real TUF metadata encodes to several KB.
var base64Literal = regexp.MustCompile("[`\"]([A-Za-z0-9+/=]{200,})[`\"]")

// inlinedTUFMetadata looks for base64-encoded TUF metadata or repositories
// embedded in Go source, which is the form the fixtures in pkg/tuf and
// pkg/apis/policy/v1alpha1 used to take.
func inlinedTUFMetadata(src []byte) string {
	for _, m := range base64Literal.FindAllSubmatch(src, -1) {
		decoded, err := base64.StdEncoding.DecodeString(string(m[1]))
		if err != nil {
			continue
		}
		if expires := tufExpiry(decoded); expires != "" {
			return "base64-encoded TUF metadata expiring " + expires
		}
		if archiveHasTUFMetadata(decoded) {
			return "base64-encoded archive containing a TUF repository"
		}
	}
	return ""
}

// tufExpiry returns the signed.expires value if b looks like TUF metadata, and
// the empty string otherwise. Anything that is not JSON is simply not TUF
// metadata for our purposes.
func tufExpiry(b []byte) string {
	var doc struct {
		Signed struct {
			Type    string `json:"_type"`
			Expires string `json:"expires"`
		} `json:"signed"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return ""
	}
	if doc.Signed.Type == "" {
		return ""
	}
	return doc.Signed.Expires
}

// archiveHasTUFMetadata reports whether a tar archive contains a root.json that
// really is TUF metadata. Matching on the filename alone would reject unrelated
// archives that happen to carry a file of that name.
func archiveHasTUFMetadata(b []byte) bool {
	var r io.Reader = bytes.NewReader(b)
	if len(b) > 2 && b[0] == 0x1f && b[1] == 0x8b {
		zr, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			return false
		}
		defer zr.Close()
		r = zr
	}

	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return false
		}
		if err != nil {
			return false
		}
		if filepath.Base(hdr.Name) != "root.json" {
			continue
		}
		content, err := io.ReadAll(io.LimitReader(tr, 1<<20))
		if err != nil {
			return false
		}
		if tufExpiry(content) != "" {
			return true
		}
	}
}

// committedFiles lists the files tracked by git, so that untracked local
// artifacts such as build output cannot fail the guardrail. It falls back to
// walking the tree where git is unavailable, e.g. in a source archive.
func committedFiles(t *testing.T, root string) []string {
	t.Helper()

	out, err := exec.Command("git", "-C", root, "ls-files", "-z").Output()
	if err == nil {
		var files []string
		for _, name := range strings.Split(string(out), "\x00") {
			if name != "" {
				files = append(files, name)
			}
		}
		return files
	}

	t.Logf("git ls-files unavailable (%v), falling back to walking %s", err, root)
	var files []string
	if err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		files = append(files, rel)
		return nil
	}); err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}
	return files
}

// repoRoot walks up from this source file to the directory holding go.mod.
func repoRoot(t *testing.T) string {
	t.Helper()

	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not determine the path of this source file")
	}
	dir := filepath.Dir(file)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find go.mod above " + file)
		}
		dir = parent
	}
}

// TestGuardDetectsFixtureShapes covers the three shapes the guardrail is meant
// to catch, so that it cannot silently degrade into always passing.
func TestGuardDetectsFixtureShapes(t *testing.T) {
	tarGz, rootJSON := NewRepo(t, testTargets())

	t.Run("metadata file", func(t *testing.T) {
		if got := tufExpiry(rootJSON); got == "" {
			t.Error("did not recognise a root.json as TUF metadata")
		}
	})

	t.Run("tarred repository", func(t *testing.T) {
		if !archiveHasTUFMetadata(tarGz) {
			t.Error("did not recognise a tarred TUF repository")
		}
	})

	t.Run("base64 in Go source", func(t *testing.T) {
		src := []byte("package x\n\nconst validRepository = `" +
			base64.StdEncoding.EncodeToString(tarGz) + "`\n")
		if got := inlinedTUFMetadata(src); got == "" {
			t.Error("did not recognise a base64-encoded repository inlined in Go source")
		}

		src = []byte("package x\n\nconst rootJSON = `" +
			base64.StdEncoding.EncodeToString(rootJSON) + "`\n")
		if got := inlinedTUFMetadata(src); got == "" {
			t.Error("did not recognise base64-encoded TUF metadata inlined in Go source")
		}
	})

	t.Run("ignores unrelated content", func(t *testing.T) {
		if got := tufExpiry([]byte(`{"hello":"world"}`)); got != "" {
			t.Errorf("plain JSON reported as TUF metadata: %s", got)
		}
		if archiveHasTUFMetadata([]byte("not an archive")) {
			t.Error("non-archive reported as a TUF repository")
		}
		if got := inlinedTUFMetadata([]byte("package x\n\nconst k = `" +
			strings.Repeat("A", 600) + "`\n")); got != "" {
			t.Errorf("unrelated base64 literal reported as TUF metadata: %s", got)
		}
	})
}
