// Copyright 2022 The Sigstore Authors.
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

package v1alpha1

import (
	"context"
	"testing"
)

// validRepository is a TUF repository that's been tarred, gzipped and base64
// encoded. These are vars because conversion to []byte seems to make them not
// constant
var (
	validRepository = []byte(`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`)

	// This is valid base64 (hello world), but should not be able to gunzip
	// untar.
	invalidRepository = []byte(`aGVsbG8gd29ybGQK`)

	// TUF Root json, generated via scaffolding
	rootJSON = `ewogInNpZ25lZCI6IHsKICAiX3R5cGUiOiAicm9vdCIsCiAgInNwZWNfdmVyc2lvbiI6ICIxLjAiLAogICJ2ZXJzaW9uIjogMSwKICAiZXhwaXJlcyI6ICIyMDIzLTA1LTE4VDIzOjE5OjQxWiIsCiAgImtleXMiOiB7CiAgICIwMDc4ZTYyZmM1MTI1NDA0YjlmOTU2ODE3NWEwY2ZlMjkwY2EwMDgzY2U0NDdjZjFmOTA1MTEzNTJhMzU4MWY1IjogewogICAgImtleXR5cGUiOiAiZWQyNTUxOSIsCiAgICAic2NoZW1lIjogImVkMjU1MTkiLAogICAgImtleWlkX2hhc2hfYWxnb3JpdGhtcyI6IFsKICAgICAic2hhMjU2IiwKICAgICAic2hhNTEyIgogICAgXSwKICAgICJrZXl2YWwiOiB7CiAgICAgInB1YmxpYyI6ICI2MmE0NDhkZTQ5ZWRhOTQ1OTQ4NjUwZjJjOGFmOGJmMDZkOWI4Y2I0MzliMTdlZDEwOGViY2ExYWQxZjU4NmVkIgogICAgfQogICB9LAogICAiMWZkNDlhYmYwNWRjZTVkZjhmOTJlMWJmNTA1ZjNhNmM5YTFjZWJjY2E2ZWJjYWIzMjUyYzYxOWNmYWFkYWFlZiI6IHsKICAgICJrZXl0eXBlIjogImVkMjU1MTkiLAogICAgInNjaGVtZSI6ICJlZDI1NTE5IiwKICAgICJrZXlpZF9oYXNoX2FsZ29yaXRobXMiOiBbCiAgICAgInNoYTI1NiIsCiAgICAgInNoYTUxMiIKICAgIF0sCiAgICAia2V5dmFsIjogewogICAgICJwdWJsaWMiOiAiZWU3ZjcyOWJhMmFmZjRhYzk0YTdiZmI4OTA2ZTAyMGFjMWFiNGUwMTljYjZhNmFkMDM0YzgyMzg4MDk3ODA3MyIKICAgIH0KICAgfSwKICAgImJiNjIyOGFhODU5MzJmZTE1NTA1NmEyZDgxNzlkYzkyMTUwYTRmYTUzNDc3OTdhYWE4NWY3OGJlOTM0OWQ1ZmEiOiB7CiAgICAia2V5dHlwZSI6ICJlZDI1NTE5IiwKICAgICJzY2hlbWUiOiAiZWQyNTUxOSIsCiAgICAia2V5aWRfaGFzaF9hbGdvcml0aG1zIjogWwogICAgICJzaGEyNTYiLAogICAgICJzaGE1MTIiCiAgICBdLAogICAgImtleXZhbCI6IHsKICAgICAicHVibGljIjogIjY4ZmVmMTg0MGZiZjg1ZWIxNjUyMjUwOGRlOWRkMjU3M2MwMjE3YjQ1YzIzZDA4ZDc4MjBmMzNjNDM5NDE2ZDgiCiAgICB9CiAgIH0sCiAgICJmNDQ5Y2YwOGZlNDc4NmZiMzUzYTNmODMwYjZkZDJlMTRmYmQ5Y2ZhNWI4NThkY2UxOGY4OWQ5ZGYyYjNiODgyIjogewogICAgImtleXR5cGUiOiAiZWQyNTUxOSIsCiAgICAic2NoZW1lIjogImVkMjU1MTkiLAogICAgImtleWlkX2hhc2hfYWxnb3JpdGhtcyI6IFsKICAgICAic2hhMjU2IiwKICAgICAic2hhNTEyIgogICAgXSwKICAgICJrZXl2YWwiOiB7CiAgICAgInB1YmxpYyI6ICI5YTc5YzZmNDNlODAyOTQ0Mzc3MDcwMzVmNmZmOWU5MzllNWYyZDJkOWNmNTRkMjk0ZTJlYjM0YWRlNDVlNzFkIgogICAgfQogICB9CiAgfSwKICAicm9sZXMiOiB7CiAgICJyb290IjogewogICAgImtleWlkcyI6IFsKICAgICAiMDA3OGU2MmZjNTEyNTQwNGI5Zjk1NjgxNzVhMGNmZTI5MGNhMDA4M2NlNDQ3Y2YxZjkwNTExMzUyYTM1ODFmNSIKICAgIF0sCiAgICAidGhyZXNob2xkIjogMQogICB9LAogICAic25hcHNob3QiOiB7CiAgICAia2V5aWRzIjogWwogICAgICIxZmQ0OWFiZjA1ZGNlNWRmOGY5MmUxYmY1MDVmM2E2YzlhMWNlYmNjYTZlYmNhYjMyNTJjNjE5Y2ZhYWRhYWVmIgogICAgXSwKICAgICJ0aHJlc2hvbGQiOiAxCiAgIH0sCiAgICJ0YXJnZXRzIjogewogICAgImtleWlkcyI6IFsKICAgICAiYmI2MjI4YWE4NTkzMmZlMTU1MDU2YTJkODE3OWRjOTIxNTBhNGZhNTM0Nzc5N2FhYTg1Zjc4YmU5MzQ5ZDVmYSIKICAgIF0sCiAgICAidGhyZXNob2xkIjogMQogICB9LAogICAidGltZXN0YW1wIjogewogICAgImtleWlkcyI6IFsKICAgICAiZjQ0OWNmMDhmZTQ3ODZmYjM1M2EzZjgzMGI2ZGQyZTE0ZmJkOWNmYTViODU4ZGNlMThmODlkOWRmMmIzYjg4MiIKICAgIF0sCiAgICAidGhyZXNob2xkIjogMQogICB9CiAgfSwKICAiY29uc2lzdGVudF9zbmFwc2hvdCI6IGZhbHNlCiB9LAogInNpZ25hdHVyZXMiOiBbCiAgewogICAia2V5aWQiOiAiMDA3OGU2MmZjNTEyNTQwNGI5Zjk1NjgxNzVhMGNmZTI5MGNhMDA4M2NlNDQ3Y2YxZjkwNTExMzUyYTM1ODFmNSIsCiAgICJzaWciOiAiZWE3MmM2NTllOWM2N2YxMGJkNjM0ZDQ1ZTE4ZjA2NjA2ODNkMjk1MzkzNThlODJhZTM5ZTJkNDg1ZGVkYmZjYWJkZDA0ODBkNWRiYTUyMWFmNzE4ZGY4MjFjYjRjNzgzNTdhMmU2NDJlMzRjOGU0NzkzOTY4ZmIzYzgxYmI2MDkiCiAgfQogXQp9`
)

func TestTrustRootValidation(t *testing.T) {
	tests := []struct {
		name        string
		trustroot   TrustRoot
		errorString string
	}{{
		name: "Should work with a valid repository",
		trustroot: TrustRoot{
			Spec: TrustRootSpec{
				Repository: &Repository{
					Root:     rootJSON,
					MirrorFS: validRepository,
					Targets:  "targets",
				},
			},
		},
	}, {
		name:        "Should fail with a missing repository.repository",
		errorString: "missing field(s): spec.repository.root",
		trustroot: TrustRoot{
			Spec: TrustRootSpec{
				Repository: &Repository{
					MirrorFS: validRepository,
					Targets:  "targets",
				},
			},
		},
	}, {
		name:        "Should fail with a missing repository.repository",
		errorString: "missing field(s): spec.repository.repository",
		trustroot: TrustRoot{
			Spec: TrustRootSpec{
				Repository: &Repository{
					Root:    rootJSON,
					Targets: "targets",
				},
			},
		},
	}, {
		name:        "Should fail with a missing repository.targets",
		errorString: "missing field(s): spec.repository.targets",
		trustroot: TrustRoot{
			Spec: TrustRootSpec{
				Repository: &Repository{
					Root:     rootJSON,
					MirrorFS: validRepository,
				},
			},
		},
	}, {
		name:        "Should fail with an invalid repository.mirrorFS, invalid base64 encoding and missing targets",
		errorString: "invalid value: failed to base64 decode: spec.repository.mirrorFS\nillegal base64 data at input byte 13\nmissing field(s): spec.repository.targets",
		trustroot: TrustRoot{
			Spec: TrustRootSpec{
				Repository: &Repository{
					Root:     rootJSON,
					MirrorFS: []byte(`badbadbadhere**`),
				},
			},
		},
	}, {
		name:        "Should fail with an invalid repository.mirrorFS, not a gzip/tar file",
		errorString: "invalid value: failed to uncompress: spec.repository.mirrorFS\ngzip: invalid header",
		trustroot: TrustRoot{
			Spec: TrustRootSpec{
				Repository: &Repository{
					Root:     rootJSON,
					MirrorFS: invalidRepository,
					Targets:  "targets",
				},
			},
		},
	}}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.trustroot.Validate(context.TODO())
			validateError(t, test.errorString, "", err)
		})
	}
}
