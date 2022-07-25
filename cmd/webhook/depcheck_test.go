//
// Copyright 2021 The Sigstore Authors.
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

package main_test

import (
	"testing"

	"knative.dev/pkg/depcheck"
)

func TestNoDeps(t *testing.T) {
	depcheck.AssertNoDependency(t, map[string][]string{
		"github.com/sigstore/policy-controller/cmd/webhook": {
			// TODO: updating go.mod makes this fail:
			// depcheck.go:126: CheckNoDependency() = github.com/sigstore/policy-controller/cmd/webhook depends on banned dependency github.com/golang/glog
			// github.com/sigstore/policy-controller/cmd/webhook
			// github.com/sigstore/policy-controller/pkg/webhook
			// github.com/sigstore/cosign/pkg/policy
			// github.com/sigstore/cosign/cmd/cosign/cli/options  # Also: [github.com/sigstore/cosign/pkg/cosign/git github.com/sigstore/cosign/pkg/cosign/git/github github.com/sigstore/cosign/pkg/cosign/git/gitlab github.com/sigstore/cosign/pkg/cosign/kubernetes github.com/sigstore/cosign/pkg/signature github.com/sigstore/policy-controller/pkg/webhook]
			// github.com/sigstore/cosign/pkg/cosign
			// github.com/sigstore/cosign/cmd/cosign/cli/fulcio/fulcioverifier/ctl
			// github.com/google/certificate-transparency-go/x509util
			// github.com/golang/glog
			// This conflicts with klog, we error on startup about
			// `-log_dir` being defined multiple times.
			// "github.com/golang/glog",
		},
	})
}
