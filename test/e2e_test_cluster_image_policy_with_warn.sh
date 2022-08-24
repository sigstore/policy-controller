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
  if [[ -z "${TOKEN_ISSUER}" ]]; then
    echo "Must specify either env variable OIDC_TOKEN or TOKEN_ISSUER"
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
COSIGN_PASSWORD="" cosign sign --key cosign-colocated-signing.key --force --allow-insecure-registry --rekor-url ${REKOR_URL} ${demoimage}
echo '::endgroup::'

echo '::group:: Verify demoimage with cosign key'
cosign verify --key cosign-colocated-signing.pub --allow-insecure-registry --rekor-url ${REKOR_URL} ${demoimage}
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
COSIGN_PASSWORD="" COSIGN_REPOSITORY="${KO_DOCKER_REPO}/remote-signature" cosign sign --key cosign-remote-signing.key --force --allow-insecure-registry --rekor-url ${REKOR_URL} ${demoimage}
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
