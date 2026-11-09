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

package webhook

import (
	"fmt"
	"os"
	"testing"
)

// TestMain gives this test binary its own TUF cache. go test runs packages
// in parallel, and the default cache (~/.sigstore/root/tuf.db) is a LevelDB
// that takes an exclusive, non-blocking lock. When two packages open it at
// once, one fails with "creating cached local store: resource temporarily
// unavailable".
func TestMain(m *testing.M) {
	os.Exit(runWithTUFRoot(m))
}

func runWithTUFRoot(m *testing.M) int {
	dir, err := os.MkdirTemp("", "webhook-tuf-root-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "creating TUF root: %v\n", err)
		return 1
	}
	defer os.RemoveAll(dir)

	if err := os.Setenv("TUF_ROOT", dir); err != nil {
		fmt.Fprintf(os.Stderr, "setting TUF_ROOT: %v\n", err)
		return 1
	}
	return m.Run()
}
