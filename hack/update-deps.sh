#!/usr/bin/env bash

# Copyright 2022 The Sigstore Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -o errexit
set -o nounset
set -o pipefail

pushd $(dirname "$0")/..
echo === Vendoring scripts
go mod vendor

source $(dirname "$0")/../vendor/knative.dev/hack/library.sh

# Override update_licenses and check_licenses to use go-licenses v1.0.0
# v1.6.0 doesn't handle stdlib modules correctly (missing module info)
# See: https://github.com/google/go-licenses/issues/302
#
# github.com/alibabacloud-go/cr-20160607 is missing a LICENSE file in its
# published module, but the GitHub repo is Apache-2.0 licensed. We copy the
# license from the sibling cr-20181201 package before running go-licenses.
function update_licenses() {
  local dst=$1
  local dir=$2
  shift
  cp "${REPO_ROOT_DIR}/vendor/github.com/alibabacloud-go/cr-20181201/LICENSE" \
     "${REPO_ROOT_DIR}/vendor/github.com/alibabacloud-go/cr-20160607/LICENSE" 2>/dev/null || true
  go_run github.com/google/go-licenses@v1.0.0 \
    save "${dir}" --save_path="${dst}" --force || \
    { echo "--- FAIL: go-licenses failed to update licenses"; return 1; }
}

function check_licenses() {
  cp "${REPO_ROOT_DIR}/vendor/github.com/alibabacloud-go/cr-20181201/LICENSE" \
     "${REPO_ROOT_DIR}/vendor/github.com/alibabacloud-go/cr-20160607/LICENSE" 2>/dev/null || true
  go_run github.com/google/go-licenses@v1.0.0 \
    check "${REPO_ROOT_DIR}/..." || \
    { echo "--- FAIL: go-licenses failed the license check"; return 1; }
}

go_update_deps "$@"

echo === Removing vendor/
rm -rf $REPO_ROOT_DIR/vendor/
