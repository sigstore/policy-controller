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

package repo

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/theupdateframework/go-tuf"
	"knative.dev/pkg/logging"
)

// TargetWithMetadata describes a TUF target with the given Name, Bytes, and
// CustomMetadata
type TargetWithMetadata struct {
	Name           string
	Bytes          []byte
	CustomMetadata []byte
}

type CustomMetadata struct {
	Usage  string `json:"usage"`
	Status string `json:"status"`
	URI    string `json:"uri"`
}

type sigstoreCustomMetadata struct {
	Sigstore CustomMetadata `json:"sigstore"`
}

// CreateRepoWithMetadata will create a TUF repo for Sigstore by adding targets
// to the Root with custom metadata.
func CreateRepoWithMetadata(ctx context.Context, targets []TargetWithMetadata) (tuf.LocalStore, string, error) {
	// TODO: Make this an in-memory fileystem.
	tmpDir := os.TempDir()
	dir := path.Join(tmpDir, "tuf")
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

	for _, t := range targets {
		logging.FromContext(ctx).Infof("Adding file: %s", t.Name)
		if err := writeStagedTarget(dir, t.Name, t.Bytes); err != nil {
			return nil, "", fmt.Errorf("failed to write staged target %s: %w", t.Name, err)
		}
		err = r.AddTargetWithExpires(t.Name, t.CustomMetadata, expires)
		if err != nil {
			return nil, "", fmt.Errorf("failed to add AddTargetWithExpires: %w", err)
		}
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

// CreateRepo creates and initializes a TUF repo for Sigstore by adding
// keys to bytes. keys are typically for a basic setup like:
// "fulcio_v1.crt.pem" - Fulcio root cert in PEM format
// "ctfe.pub" - CTLog public key in PEM format
// "rekor.pub" - Rekor public key in PEM format
// "tsa_leaf.crt.pem" - TSA leaf certificate in PEM format
// "tsa_intermediate_0.crt.pem" - TSA Intermediate certificate in PEM format
// "tsa_root.crt.pem" - TSA Intermediate certificate in PEM format
// but additional keys can be added here.
//
// This will also deduce the Usage for the keys based off the filename:
// if the filename contains:
//   - `fulcio` = it will get Usage set to `Fulcio`
//   - `ctfe` = it will get Usage set to `CTFE`
//   - `rekor` = it will get Usage set to `Rekor`
//   - `tsa` = it will get Usage set to `tsa`.
//   - Anything else will get set to `Unknown`
func CreateRepo(ctx context.Context, files map[string][]byte) (tuf.LocalStore, string, error) {
	targets := make([]TargetWithMetadata, 0, len(files))
	for name, bytes := range files {
		var usage string
		switch {
		case strings.Contains(name, "fulcio"):
			usage = "Fulcio"
		case strings.Contains(name, "ctfe"):
			usage = "CTFE"
		case strings.Contains(name, "rekor"):
			usage = "Rekor"
		case strings.Contains(name, "tsa"):
			usage = "TSA"
		default:
			usage = "Unknown"
		}
		scmActive, err := json.Marshal(&sigstoreCustomMetadata{Sigstore: CustomMetadata{Usage: usage, Status: "Active"}})
		if err != nil {
			return nil, "", fmt.Errorf("failed to marshal custom metadata for %s: %w", name, err)
		}
		targets = append(targets, TargetWithMetadata{
			Name:           name,
			Bytes:          bytes,
			CustomMetadata: scmActive,
		})
	}

	return CreateRepoWithMetadata(ctx, targets)
}

func writeStagedTarget(dir, path string, data []byte) error {
	path = filepath.Join(dir, "staged", "targets", path)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	/* #nosec G306 */
	return os.WriteFile(path, data, 0644)
}

// CompressFS archives a TUF repository so that it can be written to Secret
// for later use.
func CompressFS(fsys fs.FS, buf io.Writer, skipDirs map[string]bool) error {
	// tar > gzip > buf
	zr := gzip.NewWriter(buf)
	tw := tar.NewWriter(zr)

	err := fs.WalkDir(fsys, "repository", func(file string, d fs.DirEntry, err error) error {
		// Skip the 'keys' and 'staged' directory
		if d.IsDir() && skipDirs[d.Name()] {
			return filepath.SkipDir
		}

		// Stat the file to get the details of it.
		fi, err2 := fs.Stat(fsys, file)
		if err2 != nil {
			return fmt.Errorf("fs.Stat %s: %w", file, err2)
		}
		header, err2 := tar.FileInfoHeader(fi, file)
		if err2 != nil {
			return fmt.Errorf("FileInfoHeader %s: %w", file, err2)
		}
		header.Name = filepath.ToSlash(file)
		if err2 := tw.WriteHeader(header); err2 != nil {
			return err
		}
		// For files, write the contents.
		if !d.IsDir() {
			data, err2 := fsys.Open(file)
			if err2 != nil {
				return fmt.Errorf("opening %s: %w", file, err2)
			}
			if _, err2 := io.Copy(tw, data); err2 != nil {
				return fmt.Errorf("copying %s: %w", file, err2)
			}
		}
		return nil
	})

	if err != nil {
		tw.Close()
		zr.Close()
		return fmt.Errorf("WalkDir: %w", err)
	}

	if err := tw.Close(); err != nil {
		zr.Close()
		return fmt.Errorf("tar.NewWriter Close(): %w", err)
	}
	return zr.Close()
}

// check for path traversal and correct forward slashes
func validRelPath(p string) bool {
	if p == "" || strings.Contains(p, `\`) || strings.HasPrefix(p, "/") || strings.Contains(p, "../") {
		return false
	}
	return true
}

// Uncompress takes a TUF repository that's been compressed with Compress and
// writes to dst directory.
func Uncompress(src io.Reader, dst string) error {
	zr, err := gzip.NewReader(src)
	if err != nil {
		return err
	}
	tr := tar.NewReader(zr)

	// uncompress each element
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break // End of archive
		}
		if err != nil {
			return err
		}
		target := header.Name

		// validate name against path traversal
		if !validRelPath(header.Name) {
			return fmt.Errorf("tar contained invalid name error %q", target)
		}

		// add dst + re-format slashes according to system
		// #nosec G305
		// mitigated below
		target = filepath.Join(dst, header.Name)
		// this check is to mitigate gosec G305 (zip slip vulnerability)
		if !strings.HasPrefix(target, filepath.Clean(dst)) {
			return fmt.Errorf("%s: %s", "content filepath is tainted", header.Name)
		}
		// check the type
		switch header.Typeflag {
		// Create directories
		case tar.TypeDir:
			if _, err := os.Stat(target); err != nil {
				if err := os.MkdirAll(target, os.ModePerm); err != nil {
					return err
				}
			}
		// Write out files
		case tar.TypeReg:
			fileToWrite, err := os.OpenFile(target, os.O_CREATE|os.O_RDWR, os.FileMode(header.Mode))
			if err != nil {
				return err
			}
			// copy over contents
			for {
				_, err := io.CopyN(fileToWrite, tr, 1024)
				if err != nil {
					if errors.Is(err, io.EOF) {
						break
					}
					return err
				}
			}
			if err := fileToWrite.Close(); err != nil {
				return fmt.Errorf("failed to close file %s: %w", target, err)
			}
		}
	}
	return nil
}
