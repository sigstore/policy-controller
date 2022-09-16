// Copyright 2022 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package signaturealgo

import (
	"crypto"
	"testing"
)

func TestHashAlgorithm(t *testing.T) {
	for _, c := range []struct {
		algorithm string
		wantHash  crypto.Hash
		wantErr   bool
	}{
		{algorithm: "sha256", wantErr: false, wantHash: crypto.SHA256},
		{algorithm: "sha512", wantErr: false, wantHash: crypto.SHA512},
		{algorithm: "sha224", wantErr: false, wantHash: crypto.SHA224},
		{algorithm: "sha384", wantErr: false, wantHash: crypto.SHA384},
		{algorithm: "sha3845", wantErr: true, wantHash: crypto.SHA256},
		{algorithm: "", wantErr: false, wantHash: crypto.SHA256},
	} {
		t.Run(c.algorithm, func(t *testing.T) {
			hashCode, err := HashAlgorithm(c.algorithm)
			if hashCode != c.wantHash {
				t.Errorf("hash code: got %v, want %v", hashCode, c.wantHash)
			}
			if gotErr := err != nil; gotErr != c.wantErr {
				t.Errorf("err: got %v, want %t", err, c.wantErr)
			}
		})
	}
}
