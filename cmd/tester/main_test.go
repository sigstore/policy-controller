//
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

package main

import (
	"bytes"
	"testing"
)

func TestWriteOutput(t *testing.T) {
	tests := []struct {
		name  string
		errs  []string
		warns []string
		want  string
	}{{
		name: "success prints nothing",
	}, {
		name:  "success with warnings prints the warnings",
		warns: []string{"spec.hostNetwork is set"},
		want:  `{"warnings":["spec.hostNetwork is set"]}` + "\n",
	}, {
		name: "errors only",
		errs: []string{"no signatures found"},
		want: `{"errors":["no signatures found"]}` + "\n",
	}, {
		name:  "errors and warnings",
		errs:  []string{"no signatures found"},
		warns: []string{"spec.hostNetwork is set"},
		want:  `{"errors":["no signatures found"],"warnings":["spec.hostNetwork is set"]}` + "\n",
	}}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := writeOutput(&buf, tc.errs, tc.warns); err != nil {
				t.Fatalf("writeOutput() = %v", err)
			}
			if got := buf.String(); got != tc.want {
				t.Errorf("writeOutput() wrote %q, want %q", got, tc.want)
			}
		})
	}
}
