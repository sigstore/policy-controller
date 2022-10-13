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

export COSIGN_EXPERIMENTAL="true"

# Initialize cosign with our TUF root
cosign initialize --mirror ${TUF_MIRROR} --root ${TUF_ROOT_FILE}

# To simplify testing failures, use this function to execute a kubectl to create
# our job and verify that the failure is expected.
assert_error() {
  local KUBECTL_OUT_FILE="/tmp/kubectl.failure.out"
  match="$@"
  echo looking for ${match}
  kubectl delete job job-that-fails -n ${NS} --ignore-not-found=true
  if kubectl create -n ${NS} job job-that-fails --image=${demoimage} 2> ${KUBECTL_OUT_FILE} ; then
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
kubectl apply -f ./test/testdata/policy-controller/e2e/cip-keyless.yaml
echo '::endgroup::'

echo '::group:: Sign demo image'
if ! cosign sign --rekor-url ${REKOR_URL} --fulcio-url ${FULCIO_URL} --force --allow-insecure-registry ${demoimage} --identity-token ${OIDC_TOKEN} ; then
  echo "failed to sign with keyless"
  exit 1
fi
echo '::endgroup::'

echo '::group:: Verify demo image'
if ! cosign verify --rekor-url ${REKOR_URL} --allow-insecure-registry ${demoimage} ; then
  echo "failed to verify with keyless"
fi
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

# Create a CIP with static fail, since they are ANDed together, even though it
# passed above will now fail.
echo '::group:: Create CIP that always fails'
kubectl apply -f ./test/testdata/policy-controller/e2e/cip-static-fail.yaml
# allow things to propagate
sleep 5
echo '::endgroup::'

echo '::group:: test with static fail'
expected_error='disallowed by static policy'
assert_error ${expected_error}
echo '::endgroup::'

echo '::group:: Create CIP that always passes'
kubectl apply -f ./test/testdata/policy-controller/e2e/cip-static-pass.yaml
# allow things to propagate
sleep 5
echo '::endgroup::'

echo '::group:: test with static fail and static pass'
expected_error='disallowed by static policy'
assert_error ${expected_error}
echo '::endgroup::'

echo '::group:: Delete CIP that always fails'
kubectl delete cip image-policy-static-fail
# allow things to propagate
sleep 5
echo '::endgroup::'

echo '::group:: test with static pass should work'
# We signed this above, and there's pass always so should work
if ! kubectl create -n demo-keyless-signing job demo-works --image=${demoimage} ; then
  echo Failed to create Job in namespace with matching signature and static pass!
  exit 1
else
  echo Succcessfully created Job with signed image and static pass
fi
echo '::endgroup::'


# We did not sign this, should fail
echo '::group:: test job rejection'
if kubectl create -n demo-keyless-signing job demo2 --image=${demoimage2} ; then
  echo Failed to block unsigned Job creation!
  exit 1
else
  echo Successfully blocked Job creation with unsigned image
fi
echo '::endgroup::'

echo '::group:: Add cip with identities that match issuer/subject'
kubectl apply -f ./test/testdata/policy-controller/e2e/cip-keyless-with-identities.yaml
# make sure the reconciler has enough time to update the configmap
sleep 5
echo '::endgroup::'

# This has correct issuer/subject, so should work
echo '::group:: test job success with identities'
if ! kubectl create -n demo-keyless-signing job demo-identities-works --image=${demoimage} ; then
  echo Failed to create Job in namespace with matching issuer/subject!
  exit 1
else
  echo Succcessfully created Job with signed image keyless
fi
echo '::endgroup::'

echo '::group:: Add cip with identities that do not match issuer/subject'
kubectl apply -f ./test/testdata/policy-controller/e2e/cip-keyless-with-identities-mismatch.yaml
# make sure the reconciler has enough time to update the configmap
sleep 5
echo '::endgroup::'

echo '::group:: test job block with mismatching issuer/subject'
expected_error='none of the expected identities matched what was in the certificate'
assert_error ${expected_error}
echo '::endgroup::'

echo '::group:: Remove mismatching cip, start fresh for key'
kubectl delete cip --all
echo 'done deleting cips'
sleep 5
echo '::endgroup::'

echo '::group:: Generate New Signing Key For Colocated Signature'
COSIGN_PASSWORD="" cosign generate-key-pair
mv cosign.key cosign-colocated-signing.key
mv cosign.pub cosign-colocated-signing.pub
echo '::endgroup::'

echo '::group:: Deploy ClusterImagePolicy With Key Signing'
yq '. | .spec.authorities[0].key.data |= load_str("cosign-colocated-signing.pub")' \
  ./test/testdata/policy-controller/e2e/cip-key.yaml | \
  kubectl apply -f -
echo '::endgroup::'

echo '::group:: Create and label new namespace for verification'
kubectl create namespace demo-key-signing
kubectl label namespace demo-key-signing policy.sigstore.dev/include=true

echo '::group:: Verify blocks unsigned with the key'
if kubectl create -n demo-key-signing job demo --image=${demoimage}; then
  echo Failed to block unsigned Job creation!
  exit 1
fi
echo '::endgroup::'

echo '::group:: Sign demoimage with cosign key'
if ! COSIGN_PASSWORD="" cosign sign --key cosign-colocated-signing.key --force --allow-insecure-registry --rekor-url ${REKOR_URL} ${demoimage} ; then
  echo failed to sign demoimage with key
  exit 1
fi
echo '::endgroup::'

echo '::group:: Verify demoimage with cosign key'
if ! cosign verify --key cosign-colocated-signing.pub --allow-insecure-registry --rekor-url ${REKOR_URL} ${demoimage} ; then
  echo failed to verify demo image with cosign key
  exit 1
fi
echo '::endgroup::'

echo '::group:: test job success'
# We signed this above, this should work
if ! kubectl create -n demo-key-signing job demo --image=${demoimage} ; then
  echo Failed to create Job in namespace after signing with key!
  exit 1
else
  echo Succcessfully created Job with signed image
fi
echo '::endgroup::'

# Deploy a CIP that adds a keyless entry, that tests OR.
echo '::group:: Deploy ClusterImagePolicy With Key Signing'
yq '. | .spec.authorities[0].key.data |= load_str("cosign-colocated-signing.pub")' \
  ./test/testdata/policy-controller/e2e/cip-key-and-keyless.yaml | \
  kubectl apply -f -

# Give the policy controller a moment to update the configmap
# and pick up the change in the admission controller.
sleep 5
echo '::endgroup::'

echo '::group:: test with key and keyless, authorities OR'
if ! kubectl create -n demo-key-signing job demo-with-or --image=${demoimage} ; then
  echo Failed to create Job in namespace after adding a keyless authority, OR is not working
  exit 1
else
  echo Succcessfully created Job with signed image
fi
echo '::endgroup::'

echo '::group:: test job rejection'
# We did not sign this, should fail
if kubectl create -n demo-key-signing job demo2 --image=${demoimage2} ; then
  echo Failed to block unsigned Job creation!
  exit 1
else
  echo Successfully blocked Job creation with unsigned image
fi
echo '::endgroup::'

echo '::group:: Generate new Signing key and secret used for validating secret'
COSIGN_PASSWORD="" cosign generate-key-pair
mv cosign.key cosign-secret.key
mv cosign.pub cosign-secret.pub
kubectl -n cosign-system create secret generic cip-secret --from-file=secret=./cosign-secret.pub
echo '::endgroup::'

echo '::group:: Deploy ClusterImagePolicy with secret as the key'
kubectl apply -f ./test/testdata/policy-controller/e2e/cip-key-secret.yaml
# Give the policy controller a moment to update the configmap
# and pick up the change in the admission controller.
sleep 5
echo '::endgroup::'

echo '::group:: test with key and keyless, authorities OR'
if kubectl create -n demo-key-signing job demo-with-secret --image=${demoimage} ; then
  echo Failed to block Job in namespace after adding a secretRef
  exit 1
else
  echo Succcessfully blocked Job with secretRef key but not signed with it.
fi
echo '::endgroup::'

echo '::group:: Sign demoimage with cosign key secret'
if ! COSIGN_PASSWORD="" cosign sign --key cosign-secret.key --force --allow-insecure-registry --rekor-url ${REKOR_URL} ${demoimage} ; then
  echo failed to sign demoimage with key secret
  exit 1
fi
echo '::endgroup::'

echo '::group:: Verify demoimage with cosign key secret'
if ! cosign verify --key cosign-secret.pub --allow-insecure-registry --rekor-url ${REKOR_URL} ${demoimage} ; then
  echo failed to verify demo image with cosign key
  exit 1
fi
echo '::endgroup::'

echo '::group:: test with secret signed'
if ! kubectl create -n demo-key-signing job demo-with-secret --image=${demoimage} ; then
  echo Failed to create Job in namespace after signing with secretRef
  exit 1
else
  echo Succcessfully created Job with secretRef signed.
fi
echo '::endgroup::'


echo '::group:: Generate New Signing Key For Remote Signature'
COSIGN_PASSWORD="" cosign generate-key-pair
mv cosign.key cosign-remote-signing.key
mv cosign.pub cosign-remote-signing.pub
echo '::endgroup::'

echo '::group:: Deploy ClusterImagePolicy With Remote Public Key But Missing Source'
yq '. | .metadata.name = "image-policy-remote-source"
    | .spec.authorities[0].key.data |= load_str("cosign-remote-signing.pub")' \
  ./test/testdata/policy-controller/e2e/cip-key.yaml | \
  kubectl apply -f -

# Give the policy controller a moment to update the configmap
# and pick up the change in the admission controller.
sleep 5
echo '::endgroup::'

echo '::group:: Sign demoimage with cosign remote key'
if ! COSIGN_PASSWORD="" COSIGN_REPOSITORY="${KO_DOCKER_REPO}/remote-signature" cosign sign --key cosign-remote-signing.key --force --allow-insecure-registry --rekor-url ${REKOR_URL} ${demoimage} ; then
  echo "failed to sign with remote key"
  exit 1
fi
echo '::endgroup::'

echo '::group:: Verify demoimage with cosign remote key'
if cosign verify --key cosign-remote-signing.pub --allow-insecure-registry --rekor-url ${REKOR_URL} ${demoimage}; then
  echo "Signature should not have been verified unless COSIGN_REPOSITORY was defined"
  exit 1
fi

if ! COSIGN_REPOSITORY="${KO_DOCKER_REPO}/remote-signature" cosign verify --key cosign-remote-signing.pub --allow-insecure-registry --rekor-url ${REKOR_URL} ${demoimage}; then
  echo "Signature should have been verified when COSIGN_REPOSITORY was defined"
  exit 1
fi
echo '::endgroup::'

echo '::group:: Create test namespace and label for remote key verification'
kubectl create namespace demo-key-remote
kubectl label namespace demo-key-remote policy.sigstore.dev/include=true
echo '::endgroup::'

echo '::group:: Verify with three CIP, one without correct Source set'
if kubectl create -n demo-key-remote job demo --image=${demoimage}; then
  echo Failed to block unsigned Job creation!
  exit 1
fi
echo '::endgroup::'

echo '::group:: Deploy ClusterImagePolicy With Remote Public Key With Source'
yq '. | .metadata.name = "image-policy-remote-source"
    | .spec.authorities[0].key.data |= load_str("cosign-remote-signing.pub")
    | .spec.authorities[0] += {"source": [{"oci": env(KO_DOCKER_REPO)+"/remote-signature"}]}' \
  ./test/testdata/policy-controller/e2e/cip-key.yaml | \
  kubectl apply -f -

# Give the policy controller a moment to update the configmap
# and pick up the change in the admission controller.
sleep 5
echo '::endgroup::'

echo '::group:: Verify with three CIP, one with correct Source set'
# We signed this above and applied remote signature source location above
if ! kubectl create -n demo-key-remote job demo --image=${demoimage}; then
  echo Failed to create Job with Remote Public Key with Source
  exit 1
else
  echo Succcessfully created Job with signed image
fi
echo '::endgroup::'

echo '::group::' Cleanup
kubectl delete cip --all
kubectl delete ns demo-key-signing demo-keyless-signing demo-key-remote
rm cosign*.key cosign*.pub
echo '::endgroup::'

echo '::group:: Generate New Signing Key For Matching Resources with Labels'
COSIGN_PASSWORD="" cosign generate-key-pair
mv cosign.key cosign-match-signing.key
mv cosign.pub cosign-match-signing.pub
echo '::endgroup::'

echo '::group:: Create test namespace and label for matching Pods only in namespace'
kubectl create namespace demo-match-res-label-only
kubectl label namespace demo-match-res-label-only policy.sigstore.dev/include=true
echo '::endgroup::'

echo '::group:: Deploy ClusterImagePolicy With Matching Resource Labels for Pods'
yq '. | .metadata.name = "image-policy-match-label"
    | .spec.authorities[0].key.data |= load_str("cosign-match-signing.pub")' \
  ./test/testdata/policy-controller/e2e/cip-match-resource-label.yaml | \
  kubectl apply -f -

# Give the policy controller a moment to update the configmap
# and pick up the change in the admission controller.
sleep 5
echo '::endgroup::'

# For pods that do not match labels, meaning there are no matching policies, we
# need to flip the default behaviour of deny => allow.
# But, let's flip it here before the tests to make sure matched pods are
# denied properly.
echo '::group:: Change no-match policy to warn'
kubectl patch configmap/config-policy-controller \
  --namespace cosign-system \
  --type merge \
  --patch '{"data":{"no-match-policy":"allow"}}'
# allow for propagation
sleep 5
echo '::endgroup::'

echo '::group:: Verify with CIP that blocks a pod with valid labels but a different key'
if kubectl run -n demo-match-res-label-only demo-invalid-key --image=${demoimage} -l match=match; then
  echo Failed to block signed Pod with wrong key creation!
  exit 1
fi
echo '::endgroup::'


echo '::group:: Verify with CIP that pods can get deployed due to unmatching labels'
if ! kubectl run -n demo-match-res-label-only demo-valid-key --image=${demoimage}  -l test=staging; then
  echo Failed to create Pod when labels are not matching the CIP
  exit 1
else
  echo Succcessfully created Pod when labels are not matching the CIP
fi
echo '::endgroup::'

echo '::group:: Sign demoimage with cosign key'
if ! COSIGN_PASSWORD="" cosign sign --key cosign-match-signing.key --force --allow-insecure-registry --rekor-url ${REKOR_URL} ${demoimage} ; then
  echo failed to sign demoimage with key
  exit 1
fi
echo '::endgroup::'

echo '::group:: Verify demoimage with cosign key'
if ! cosign verify --key cosign-match-signing.pub --allow-insecure-registry --rekor-url ${REKOR_URL} ${demoimage} ; then
  echo failed to verify demo image with cosign key
  exit 1
fi
echo '::endgroup::'

echo '::group:: Verify with CIP that blocks the pod using a valid key and labels'
if ! kubectl run -n demo-match-res-label-only demo-valid-key-labels --image=${demoimage} -l match=match; then
  echo Failed to create Pod with a valid key and matching labels
  exit 1
else
  echo Succcessfully created Pod with a valid key and matching labels
fi
echo '::endgroup::'

echo '::group::' Cleanup
kubectl delete cip --all
kubectl delete ns demo-match-res-label-only
rm cosign*.key cosign*.pub
echo '::endgroup::'

demoimageSignature="quay.io/jetstack/cert-manager-acmesolver:v1.9.1"

echo '::group:: Create test namespace and label for signature digest sha512'
kubectl create namespace demo-key-sha512
kubectl label namespace demo-key-sha512 policy.sigstore.dev/include=true
echo '::endgroup::'

echo '::group:: Deploy ClusterImagePolicy With signature digest sha512'
yq '. | .metadata.name = "image-policy-sha512-key"' \
  ./test/testdata/policy-controller/e2e/cip-key-hash-algorithm.yaml | \
  kubectl apply -f -
echo '::endgroup::'

echo '::group:: Verify ClusterImagePolicy With signature digest sha512 using a pod'
# We use a signed image provided by jetstack for cert-manager-acmesolver:v1.9.1
if ! kubectl run -n demo-key-sha512 job demo-sha512-key --image=${demoimageSignature}; then
  echo Failed to create Pod with signature digest sha512
  exit 1
else
  echo Succcessfully created Pod with signature digest sha512
fi
echo '::endgroup::'

echo '::group::' Cleanup
kubectl delete cip --all
kubectl delete ns demo-key-sha512
echo '::endgroup::'

# Publish the first test image
echo '::group:: publish test image demoEphemeralImage'
pushd $(mktemp -d)
go mod init example.com/demo
cat <<EOF > main.go
package main
import (
  "fmt"
  "time"
)
func main() {
  // Calling Sleep method
  time.Sleep(8 * time.Minute)

  fmt.Println("Sleep Over.....")
}
EOF

sed -i'' -e "s@TIMESTAMP@${TIMESTAMP}@g" main.go
cat main.go
export demoEphemeralImage=`ko publish -B example.com/demo`
echo Created image $demoEphemeralImage
popd
echo '::endgroup::'

echo '::group:: Deploy ClusterImagePolicy with keyless signing'
kubectl apply -f ./test/testdata/policy-controller/e2e/cip-keyless.yaml
echo '::endgroup::'

echo '::group:: Sign demo image'
if ! cosign sign --rekor-url ${REKOR_URL} --fulcio-url ${FULCIO_URL} --force --allow-insecure-registry ${demoEphemeralImage} --identity-token ${OIDC_TOKEN} ; then
  echo "failed to sign with keyless"
  exit 1
fi
echo '::endgroup::'

echo '::group:: Verify demo image'
if ! cosign verify --rekor-url ${REKOR_URL} --allow-insecure-registry ${demoEphemeralImage} ; then
  echo "failed to verify with keyless"
fi
echo '::endgroup::'

echo '::group:: Create test namespace and label for verification'
export NS=demo-ephemeral-verification
kubectl create namespace ${NS}
kubectl label namespace ${NS} policy.sigstore.dev/include=true
echo '::endgroup::'

echo '::group:: test pod success'
# We signed this above, this should work
if ! kubectl run -n ${NS} poddemo --image=${demoEphemeralImage} ; then
  echo Failed to create Pod in namespace with matching signature!
  exit 1
else
  echo Succcessfully created Pod with signed image
fi
echo '::endgroup::'

echo '::group:: Set no-match policy to deny'
kubectl patch configmap/config-policy-controller \
  --namespace cosign-system \
  --type merge \
  --patch '{"data":{"no-match-policy":"deny"}}'
# allow for propagation
sleep 10
echo '::endgroup::'

ephemeralContainerImage="busybox@sha256:9810966b5f712084ea05bf28fc8ba2c8fb110baa2531a10e2da52c1efc504698"

echo '::group:: test rejection of ephemeral container that does not have any signature'
# We want to validate that ephemeral containers are validated, and rejected for this example
if kubectl debug poddemo -n ${NS} --image=${ephemeralContainerImage} ; then
  echo Failed to block EphemeralContainer for Pod in namespace with no matching signature!
  exit 1
else
  echo Succcessfully created EphemeralContainer for Pod without any valid signed image
fi
echo '::endgroup::'

echo '::group::' Cleanup
kubectl delete cip --all
kubectl delete ns ${NS}
echo '::endgroup::'
