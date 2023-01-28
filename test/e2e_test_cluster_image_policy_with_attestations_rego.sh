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
kubectl create namespace demo-attestations-rego
kubectl label namespace demo-attestations-rego policy.sigstore.dev/include=true
export NS=demo-attestations-rego
echo '::endgroup::'

echo '::group:: Create CIP that requires keyless signature'
kubectl apply -f ./test/testdata/policy-controller/e2e/cip-keyless.yaml
# allow things to propagate
sleep 5
echo '::endgroup::'

# This image has not been signed at all, so should get auto-reject
echo '::group:: test job rejection'
expected_error='no matching signatures'
assert_error ${expected_error}
echo '::endgroup::'

echo '::group:: Sign demoimage with keyless'
COSIGN_EXPERIMENTAL=1 cosign sign --rekor-url ${REKOR_URL} --fulcio-url ${FULCIO_URL} --yes --allow-insecure-registry ${demoimage} --identity-token ${OIDC_TOKEN}
echo '::endgroup::'

echo '::group:: Create CIP that requires keyless custom attestation with policy that requires data == "foobar e2e test"'
kubectl apply -f ./test/testdata/policy-controller/e2e/cip-keyless-with-attestations-rego.yaml
# allow things to propagate
sleep 5
echo '::endgroup::'

# This image has been signed, but does not have an attestation, so should fail.
echo '::group:: test job rejection'
expected_error='no matching attestations'
assert_error ${expected_error}
echo '::endgroup::'

# Ok, cool. So attest and it should still fail because the data does not match.
echo '::group:: Create one keyless attestation with incorrect data and verify it'
echo -n 'barfoo e2e test' > ./predicate-file-custom-fails
COSIGN_EXPERIMENTAL=1 cosign attest --predicate ./predicate-file-custom-fails --fulcio-url ${FULCIO_URL} --rekor-url ${REKOR_URL} --allow-insecure-registry --yes ${demoimage} --identity-token ${OIDC_TOKEN}

COSIGN_EXPERIMENTAL=1 cosign verify-attestation --type=custom --rekor-url ${REKOR_URL} --allow-insecure-registry --certificate-identity-regexp='.*'  --certificate-oidc-issuer-regexp='.*' ${demoimage}
echo '::endgroup::'

# This image has been signed, and has attestation, but data is not right
echo '::group:: test job rejection because the data does not match wanted policy'
expected_error='failed evaluating rego policy for type custom-match-predicate: policy is not compliant for query'
assert_error ${expected_error}
echo '::endgroup::'

# Create another attestation with the data to match what our policy wants.
echo '::group:: Create another keyless attestation with correct data and verify it'
echo -n 'foobar e2e test' > ./predicate-file-custom-works
COSIGN_EXPERIMENTAL=1 cosign attest --predicate ./predicate-file-custom-works --fulcio-url ${FULCIO_URL} --rekor-url ${REKOR_URL} --allow-insecure-registry --yes ${demoimage} --identity-token ${OIDC_TOKEN}

COSIGN_EXPERIMENTAL=1 cosign verify-attestation --type=custom --rekor-url ${REKOR_URL} --allow-insecure-registry --certificate-identity-regexp='.*'  --certificate-oidc-issuer-regexp='.*' ${demoimage}
echo '::endgroup::'

echo '::group:: test job success'
# We signed this with keyless and it has a keyless attestation, so should
# pass.
export KUBECTL_SUCCESS_FILE="/tmp/kubectl.success.out"
if ! kubectl create -n ${NS} job demo --image=${demoimage} 2> ${KUBECTL_SUCCESS_FILE} ; then
  echo Failed to create job with keyless signature and an attestation
  cat ${KUBECTL_SUCCESS_FILE}
  exit 1
else
  echo Created the job with keyless signature and an attestation
fi
kubectl delete -n ${NS} job demo
echo '::endgroup::'

echo '::group:: Generate New Signing Key that we use for key-ful signing'
COSIGN_PASSWORD="" cosign generate-key-pair
echo '::endgroup::'

# Ok, so now we have satisfied the keyless requirements, one signature, one
# custom attestation. Let's now do it for 'keyful' one.
echo '::group:: Create CIP that requires a keyful signature'
yq '. | .spec.authorities[0].key.data |= load_str("cosign.pub")' ./test/testdata/policy-controller/e2e/cip-key.yaml | kubectl apply -f -

# Give the policy controller a moment to update the configmap
# and pick up the change in the admission controller.
sleep 5
echo '::endgroup::'

# This image has been signed with keyless, but does not have a keyful signature
# so should fail
echo '::group:: test job rejection'
expected_error='no matching signatures'
assert_error ${expected_error}
echo '::endgroup::'

# Sign it with key
echo '::group:: Sign demoimage with key, and add to rekor'
COSIGN_EXPERIMENTAL=1 COSIGN_PASSWORD="" cosign sign --key cosign.key --yes --allow-insecure-registry --rekor-url ${REKOR_URL} ${demoimage}
echo '::endgroup::'

echo '::group:: Verify demoimage with cosign key'
COSIGN_EXPERIMENTAL=1 cosign verify --key cosign.pub --rekor-url ${REKOR_URL} --allow-insecure-registry --certificate-identity-regexp='.*' --certificate-oidc-issuer-regexp='.*' ${demoimage}
echo '::endgroup::'

# Ok, so now we have satisfied the keyless requirements, one signature, one
# custom attestation, and one 'keyful' one. But it will now be missing a
# keyful attestation, so let's add that requirement.
echo '::group:: Create CIP that requires a keyful attestation'
yq '. | .spec.authorities[0].key.data |= load_str("cosign.pub")' ./test/testdata/policy-controller/e2e/cip-key-with-attestations-rego.yaml | kubectl apply -f -

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

# Fine, so create an attestation for it that's different from the keyless one
echo '::group:: create keyful attestation, add add to rekor'
echo -n 'foobar key e2e test' > ./predicate-file-key-custom
COSIGN_EXPERIMENTAL=1 COSIGN_PASSWORD="" cosign attest --predicate ./predicate-file-key-custom --rekor-url ${REKOR_URL} --key ./cosign.key --allow-insecure-registry --yes ${demoimage}

COSIGN_EXPERIMENTAL=1 cosign verify-attestation --key ./cosign.pub --allow-insecure-registry --rekor-url ${REKOR_URL} --certificate-identity-regexp='.*'  --certificate-oidc-issuer-regexp='.*' ${demoimage}
echo '::endgroup::'

echo '::group:: test job success with key / keyless'
# We signed this with keyless and key and it has a key/keyless attestation, so
# should pass.
if ! kubectl create -n ${NS} job demo2 --image=${demoimage} 2> ${KUBECTL_SUCCESS_FILE} ; then
  echo Failed to create job with both key/keyless signatures and attestations
  cat ${KUBECTL_SUCCESS_FILE}
  exit 1
else
  echo Created the job with keyless/key signature and an attestations
fi
echo '::endgroup::'

echo '::group::' Cleanup
kubectl delete cip --all
kubectl delete ns ${NS}
rm cosign.key cosign.pub
echo '::endgroup::'
