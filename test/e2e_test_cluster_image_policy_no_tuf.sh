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

if [[ "${NON_REPRODUCIBLE}"=="1" ]]; then
  echo "creating non-reproducible build by adding a timestamp"
  export TIMESTAMP=`date +%s`
else
  export TIMESTAMP="TIMESTAMP"
fi

# To simplify testing failures, use this function to execute a kubectl to create
# our job and verify that the failure is expected.
assert_error() {
  local KUBECTL_OUT_FILE="/tmp/kubectl.failure.out"
  match="$@"
  echo looking for ${match}
  kubectl delete job demo -n ${NS} --ignore-not-found=true
  if kubectl create -n ${NS} job demo --image=${demoimage} 2> ${KUBECTL_OUT_FILE} ; then
    echo Failed to block expected Job failure!
    exit 1
  else
    echo Successfully blocked Job creation with expected error: "${match}"
    if ! grep -q "${match}" ${KUBECTL_OUT_FILE} ; then
      echo Did not get expected failure message, wanted "${match}", got
      cat ${KUBECTL_OUT_FILE}
      exit 1
    fi
  fi
}

# Publish test image
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

echo '::group:: Create and label new namespace for verification'
kubectl create namespace demo-no-tuf
kubectl label namespace demo-no-tuf policy.sigstore.dev/include=true
export NS=demo-no-tuf
echo '::endgroup::'

echo '::group:: Generate New Signing Key that we use for key-ful signing'
COSIGN_PASSWORD="" cosign generate-key-pair
echo '::endgroup::'

# Create CIP that requires a signature with a key.
echo '::group:: Create CIP that requires a keyful signature'
yq '. | .spec.authorities[0].key.data |= load_str("cosign.pub")' ./test/testdata/policy-controller/e2e/cip-key-no-rekor.yaml | kubectl apply -f -

# Give the policy controller a moment to update the configmap
# and pick up the change in the admission controller.
sleep 5
echo '::endgroup::'

# This image has not been signed with our key
# so should fail
echo '::group:: test job rejection'
expected_error='no matching signatures'
assert_error ${expected_error}
echo '::endgroup::'

# Sign it with key
echo '::group:: Sign demoimage with key, do not add to rekor'
COSIGN_PASSWORD="" cosign sign --no-tlog-upload --key cosign.key  --allow-insecure-registry ${demoimage}
echo '::endgroup::'

# TODO(vaikas): This fails because it doesn't have a Rekor entry. Which it obvs
# does not because of --no-tlog-upload above.
#echo '::group:: Verify demoimage with cosign key'
#cosign verify --key cosign.pub --allow-insecure-registry ${demoimage}
#echo '::endgroup::'

# Then let's test attestations work too with key.
echo '::group:: Create CIP that requires a keyful attestation'
yq '. | .spec.authorities[0].key.data |= load_str("cosign.pub")' ./test/testdata/policy-controller/e2e/cip-key-with-attestations-no-rekor.yaml | kubectl apply -f -

# Give the policy controller a moment to update the configmap
# and pick up the change in the admission controller.
sleep 5
echo '::endgroup::'

# This image has been signed with key, but does not have a key attestation
# so should fail
echo '::group:: test job rejection'
expected_error='no matching attestations'
assert_error ${expected_error}
echo '::endgroup::'

# Fine, so create an attestation for it.
echo '::group:: create keyful attestation, do not add to rekor'
echo -n 'foobar key e2e test' > ./predicate-file-key-custom
COSIGN_PASSWORD="" cosign attest --predicate ./predicate-file-key-custom --key ./cosign.key --allow-insecure-registry --no-tlog-upload ${demoimage}

# TODO(vaikas): This again fails though it really shouldn't.
#cosign verify-attestation --key ./cosign.pub --allow-insecure-registry ${demoimage}
echo '::endgroup::'

export KUBECTL_SUCCESS_FILE="/tmp/kubectl.success.out"
echo '::group:: test job success with key signature and key attestation'
# We signed this with key and it has a key attestation, so should pass.
if ! kubectl create -n ${NS} job demo2 --image=${demoimage} 2> ${KUBECTL_SUCCESS_FILE} ; then
  echo Failed to create job with both key signature and attestation
  cat ${KUBECTL_SUCCESS_FILE}
  exit 1
else
  echo Created the job with key signature and an attestation
fi
echo '::endgroup::'

echo '::group::' Cleanup
kubectl delete cip --all
kubectl delete ns ${NS}
rm cosign.key cosign.pub
echo '::endgroup::'
