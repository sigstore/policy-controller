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
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing/fstest"
	"time"

	"net/http"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore/pkg/tuf"
	"github.com/theupdateframework/go-tuf/v2/metadata"
	tufconfig "github.com/theupdateframework/go-tuf/v2/metadata/config"
	"github.com/theupdateframework/go-tuf/v2/metadata/updater"
	"sigs.k8s.io/release-utils/version"
)

var (
	// uaString is meant to resemble the User-Agent sent by browsers with requests.
	// See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/User-Agent
	uaString = fmt.Sprintf("cosign/%s (%s; %s)", version.GetVersionInfo().GitVersion, runtime.GOOS, runtime.GOARCH)
)

func CompressFS(fsys fs.FS, buf io.Writer, skipDirs map[string]bool) error {
	// tar > gzip > buf
	zr := gzip.NewWriter(buf)
	tw := tar.NewWriter(zr)

	walkErr := fs.WalkDir(fsys, "repository", func(file string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			// If we encounter an error walking, just return it and give up.
			return walkErr
		}
		// Skip the 'keys' and 'staged' directory
		if d.IsDir() && skipDirs[d.Name()] {
			return filepath.SkipDir
		}

		// Stat the file to get the details of it.
		fi, err := fs.Stat(fsys, file)
		if err != nil {
			return fmt.Errorf("fs.Stat %s: %w", file, err)
		}
		header, err := tar.FileInfoHeader(fi, file)
		if err != nil {
			return fmt.Errorf("FileInfoHeader %s: %w", file, err)
		}
		header.Name = filepath.ToSlash(file)
		if err := tw.WriteHeader(header); err != nil {
			return err
		}
		// For files, write the contents.
		if !d.IsDir() {
			data, err := fsys.Open(file)
			if err != nil {
				return fmt.Errorf("opening %s: %w", file, err)
			}
			if _, err := io.Copy(tw, data); err != nil {
				return fmt.Errorf("copying %s: %w", file, err)
			}
		}
		return nil
	})

	if walkErr != nil {
		tw.Close()
		zr.Close()
		return fmt.Errorf("WalkDir: %w", walkErr)
	}

	if err := tw.Close(); err != nil {
		zr.Close()
		return fmt.Errorf("tar.NewWriter Close(): %w", err)
	}
	return zr.Close()
}

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

		target, err := sanitizeArchivePath(dst, header.Name)
		// validate name against path traversal
		if err != nil {
			return err
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
			if header.Mode < 0 && int64(uint32(header.Mode)) != header.Mode { //nolint:gosec // disable G115
				return errors.New("invalid mode value in tar header")
			}
			fileToWrite, err := os.OpenFile(target, os.O_CREATE|os.O_RDWR, os.FileMode(header.Mode)) //nolint:gosec // disable G115
			if err != nil {
				return err
			}
			// copy over contents in chunks for security reasons
			// G110: Potential DoS vulnerability via decompression bomb
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

// From https://github.com/securego/gosec/issues/324
func sanitizeArchivePath(d, t string) (v string, err error) {
	v = filepath.Join(d, t)
	if strings.HasPrefix(v, filepath.Clean(d)) {
		return v, nil
	}

	return "", fmt.Errorf("%s: %s", "content filepath is tainted", t)
}

// UncompressMemFS takes a TUF repository that's been compressed with CompressFS
// and returns FS backed by memory.
func UncompressMemFS(src io.Reader, stripPrefix string) (fs.FS, error) {
	testFS := fstest.MapFS{}

	zr, err := gzip.NewReader(src)
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	tr := tar.NewReader(zr)

	// uncompress each element
	for {
		header, err := tr.Next()
		// EOF is unwrapped
		//nolint:errorlint
		if err == io.EOF {
			break // End of archive
		}
		if err != nil {
			return nil, err
		}
		target, err := sanitizeArchivePath("/", header.Name)
		// validate name against path traversal
		if err != nil {
			return nil, err
		}

		// Remove the prefix if given. Note that paths are relative to root, so
		// no '/' is allowed, so we always remove that.
		target = strings.TrimPrefix(target, stripPrefix)
		target = strings.TrimPrefix(target, "/")
		// check the type
		switch header.Typeflag {
		// Create directories
		case tar.TypeDir:
			testFS[target] = &fstest.MapFile{
				Mode:    os.ModeDir,
				ModTime: header.ModTime,
			}
		// Write out files
		case tar.TypeReg:
			data := make([]byte, header.Size)
			_, err := tr.Read(data)
			// EOF is unwrapped
			//nolint:errorlint
			if err != nil && err != io.EOF {
				return nil, fmt.Errorf("reading file %s : %w", header.Name, err)
			}
			if header.Mode < 0 && int64(uint32(header.Mode)) != header.Mode { //nolint:gosec // disable G115
				return nil, errors.New("invalid mode value in tar header")
			}
			testFS[target] = &fstest.MapFile{
				Data:    data,
				Mode:    os.FileMode(header.Mode), //nolint:gosec // disable G115
				ModTime: header.ModTime,
			}
		}
	}
	return testFS, nil
}

// fsFetcher implements the go-tuf v2 fetcher.Fetcher interface using an fs.FS.
type fsFetcher struct {
	fsys    fs.FS
	baseURL string
}

func (f *fsFetcher) DownloadFile(urlPath string, maxLength int64, timeout time.Duration) ([]byte, error) {
	path := strings.TrimPrefix(urlPath, f.baseURL)
	path = strings.TrimPrefix(path, "/")
	data, err := fs.ReadFile(f.fsys, path)
	if err != nil {
		// Return ErrDownloadHTTP with 404 so the TUF updater recognizes missing
		// files (e.g. during root rotation when 2.root.json doesn't exist).
		return nil, &metadata.ErrDownloadHTTP{StatusCode: http.StatusNotFound, URL: urlPath}
	}
	if maxLength > 0 && int64(len(data)) > maxLength {
		return nil, fmt.Errorf("file %s exceeds max length %d", path, maxLength)
	}
	return data, nil
}

// ClientFromSerializedMirror will construct a TUF updater by
// unzip/untar the repository and constructing an in-memory TUF
// updater for it. Will also Refresh it.
func ClientFromSerializedMirror(_ context.Context, repo, rootJSON []byte, targets, stripPrefix string) (*updater.Updater, error) {
	tufFS, err := UncompressMemFS(bytes.NewReader(repo), stripPrefix)
	if err != nil {
		return nil, fmt.Errorf("failed to uncompress: %w", err)
	}

	const baseURL = "mem://repo/"
	cfg, err := tufconfig.New(baseURL, rootJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to create TUF config: %w", err)
	}
	cfg.Fetcher = &fsFetcher{fsys: tufFS, baseURL: baseURL}
	cfg.RemoteTargetsURL = baseURL + targets + "/"
	cfg.DisableLocalCache = true
	cfg.PrefixTargetsWithHash = true

	u, err := updater.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create TUF updater: %w", err)
	}
	if err := u.Refresh(); err != nil {
		return nil, fmt.Errorf("failed to refresh TUF updater: %w", err)
	}

	if len(u.GetTopLevelTargets()) == 0 {
		return nil, errors.New("there are no valid targetfiles in TUF repo")
	}
	return u, nil
}

// ClientFromRemote will construct a TUF updater from a root, and mirror
func ClientFromRemote(_ context.Context, mirror string, rootJSON []byte, targets string) (*updater.Updater, error) {
	cfg, err := tufconfig.New(mirror, rootJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to create TUF config: %w", err)
	}
	cfg.RemoteTargetsURL = mirror + "/" + targets + "/"
	cfg.DisableLocalCache = true
	cfg.PrefixTargetsWithHash = true

	u, err := updater.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create TUF updater: %w", err)
	}
	if err := u.Refresh(); err != nil {
		return nil, fmt.Errorf("failed to refresh TUF updater: %w", err)
	}

	if len(u.GetTopLevelTargets()) == 0 {
		return nil, errors.New("there are no valid targetfiles in TUF repo")
	}
	return u, nil
}

var (
	mu          sync.RWMutex
	timestamp   time.Time
	trustedRoot *root.TrustedRoot
)

// GetTrustedRoot returns the trusted root for the TUF repository.
func GetTrustedRoot(ctx context.Context) (*root.TrustedRoot, error) {
	resyncPeriodDuration := FromContextOrDefaults(ctx)
	now := time.Now().UTC()
	// check if timestamp has never been set or if the current time
	// is after the current timestamp value plus the included resync duration
	if timestamp.IsZero() || now.After(timestamp.Add(resyncPeriodDuration)) {
		mu.Lock()
		defer mu.Unlock()

		tufClient, err := tuf.NewFromEnv(context.Background())
		if err != nil {
			return nil, fmt.Errorf("initializing tuf: %w", err)
		}
		// TODO: add support for custom trusted root path
		targetBytes, err := tufClient.GetTarget("trusted_root.json")
		if err != nil {
			return nil, fmt.Errorf("error getting targets: %w", err)
		}
		trustedRoot, err = root.NewTrustedRootFromJSON(targetBytes)
		if err != nil {
			return nil, fmt.Errorf("error creating trusted root: %w", err)
		}

		timestamp = now

		return trustedRoot, nil
	}

	mu.RLock()
	defer mu.RUnlock()

	return trustedRoot, nil
}
