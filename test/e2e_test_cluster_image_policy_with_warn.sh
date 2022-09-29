#!/usr/bin/env bash
#
# Copyright 2022 The Sigstore Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


set -ex

if [[ -z "${OIDC_TOKEN}" ]]; then
  if [[ -z "${ISSUER_URL}" ]]; then
    echo "Must specify either env variable OIDC_TOKEN or ISSUER_URL"
    exit 1
  else
    export OIDC_TOKEN=`curl -s ${ISSUER_URL}`
  fi
fi

if [[ -z "${KO_DOCKER_REPO}" ]]; then
  echo "Must specify env variable KO_DOCKER_REPO"
  exit 1
fi

if [[ -z "${FULCIO_URL}" ]]; then
  echo "Must specify env variable FULCIO_URL"
  exit 1
fi

if [[ -z "${REKOR_URL}" ]]; then
  echo "Must specify env variable REKOR_URL"
  exit 1
fi

if [[ -z "${TUF_ROOT_FILE}" ]]; then
  echo "must specify env variable TUF_ROOT_FILE"
  exit 1
fi

if [[ -z "${TUF_MIRROR}" ]]; then
  echo "must specify env variable TUF_MIRROR"
  exit 1
fi

if [[ "${NON_REPRODUCIBLE}"=="1" ]]; then
  echo "creating non-reproducible build by adding a timestamp"
  export TIMESTAMP=`date +%s`
else
  export TIMESTAMP="TIMESTAMP"
fi

# Initialize cosign with our TUF root
cosign initialize --mirror ${TUF_MIRROR} --root ${TUF_ROOT_FILE}

# To simplify testing warnings, use this function to execute a kubectl to create
# our job and verify that the warning is as expected.
assert_warning() {
  local KUBECTL_OUT_FILE="/tmp/kubectl.warning.out"
  match="$@"
  echo looking for ${match}
  kubectl delete job job-that-warns -n ${NS} --ignore-not-found=true
  if ! kubectl create -n ${NS} job job-that-warns --image=${demoimage2} 2> ${KUBECTL_OUT_FILE} ; then
    echo Failed to create Job when expected to warn!
    exit 1
  else
    echo Successfully created job, checking warning: "${match}"
    if ! grep -q "${match}" ${KUBECTL_OUT_FILE} ; then
      echo Did not get expected warning message, wanted "${match}", got
      cat ${KUBECTL_OUT_FILE}
      exit 1
    fi
  fi
}

# Publish the first test image
echo '::group:: publish test image demoimage'
pushd $(mktemp -d)
go mod init example.com/demo
cat <<EOF > main.go
package main
import "fmt"
func main() {
  fmt.Println("hello world TIMESTAMP")
}
EOF

sed -i'' -e "s@TIMESTAMP@${TIMESTAMP}@g" main.go
cat main.go
export demoimage=`ko publish -B example.com/demo`
echo Created image $demoimage
popd
echo '::endgroup::'

# Publish the second test image
echo '::group:: publish test image demoimage'
pushd $(mktemp -d)
go mod init example.com/demo
cat <<EOF > main.go
package main
import "fmt"
func main() {
  fmt.Println("hello world 2 TIMESTAMP")
}
EOF
sed -i'' -e "s@TIMESTAMP@${TIMESTAMP}@g" main.go
cat main.go
export demoimage2=`ko publish -B example.com/demo`
popd
echo '::endgroup::'

echo '::group:: Deploy ClusterImagePolicy with keyless signing'
kubectl apply -f ./test/testdata/policy-controller/e2e/cip-keyless-warn.yaml
echo '::endgroup::'

echo '::group:: Sign demo image'
COSIGN_EXPERIMENTAL=1 cosign sign --rekor-url ${REKOR_URL} --fulcio-url ${FULCIO_URL} --force --allow-insecure-registry ${demoimage} --identity-token ${OIDC_TOKEN}
echo '::endgroup::'

echo '::group:: Verify demo image'
COSIGN_EXPERIMENTAL=1 cosign verify --rekor-url ${REKOR_URL} --allow-insecure-registry ${demoimage}
echo '::endgroup::'

echo '::group:: Create test namespace and label for verification'
kubectl create namespace demo-keyless-signing
kubectl label namespace demo-keyless-signing policy.sigstore.dev/include=true
export NS=demo-keyless-signing
echo '::endgroup::'

echo '::group:: test job success'
# We signed this above, this should work
if ! kubectl create -n demo-keyless-signing job demo --image=${demoimage} ; then
  echo Failed to create Job in namespace with matching signature!
  exit 1
else
  echo Succcessfully created Job with signed image
fi
echo '::endgroup::'

# We did not sign this, should warn but not fail
echo '::group:: test job admission with warning'
expected_warn='Warning: failed policy: image-policy-keyless-warn'
assert_warning ${expected_warn}
echo '::endgroup::'

# Change to an image that does not match any policies
demoimage2="quay.io/jetstack/cert-manager-acmesolver:v1.9.1"

# Then test the unmatched policy behaviour with default, which is allow
echo '::group:: test no-match policy allow'
if ! kubectl create -n demo-keyless-signing job demo-works --image=${demoimage2} ; then
  echo Failed to create Job in namespace with no matching policies, but allow
  exit 1
else
  echo Succcessfully created Job because no matching policy and allow
fi
echo '::endgroup::'

echo '::group:: Change no-match policy to warn'
kubectl patch configmap/config-policy-controller \
  --namespace cosign-system \
  --type merge \
  --patch '{"data":{"no-match-policy":"warn"}}'
# allow for propagation
sleep 5
echo '::endgroup::'

echo '::group:: test job admission with warning'
expected_warn='Warning: no matching policies:'
assert_warning ${expected_warn}
echo '::endgroup::'

echo '::group:: Change no-match policy to deny'
kubectl patch configmap/config-policy-controller \
  --namespace cosign-system \
  --type merge \
  --patch '{"data":{"no-match-policy":"deny"}}'
# allow for propagation
sleep 5
echo '::endgroup::'

echo '::group:: test no-match policy deny'
if kubectl create -n demo-keyless-signing job demo-should-not-work --image=${demoimage2} ; then
  echo Failed to block Job with no matching policy and deny
  exit 1
else
  echo Successfully blocked Job in namespace with no matching policies, and deny
fi
echo '::endgroup::'

echo '::group::' Cleanup
kubectl delete cip --all
kubectl delete ns demo-keyless-signing
echo '::endgroup::'
