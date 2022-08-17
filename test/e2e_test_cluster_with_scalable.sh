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

unset TUF_ROOT

# Initialize cosign with our TUF root
cosign initialize --mirror ${TUF_MIRROR} --root ./root.json

# To simplify testing failures, use this function to execute a kubectl to scale
# deployment up and verify that the failure is expected.
assert_error() {
  local KUBECTL_OUT_FILE="/tmp/kubectl.failure.out"
  match="$@"
  echo looking for ${match}
  if kubectl patch -n ${NS} deployment test-deployment --type "json" -p '[{"op":"replace", "path":"/spec/replicas", "value":5}]' 2> ${KUBECTL_OUT_FILE} ; then
  echo Failed to block expected scaling failure!
    exit 1
  else
    echo Successfully blocked scaling with expected error: "${match}"
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
import (
"fmt"
"time"
)
func main() {
  fmt.Println("hello world deployment TIMESTAMP")
  time.Sleep(10*time.Minute)
}
EOF

sed -i'' -e "s@TIMESTAMP@${TIMESTAMP}@g" main.go
cat main.go
export demoimage=`ko publish -B example.com/demo`
echo Created image $demoimage
popd
echo '::endgroup::'

echo '::group:: Create test namespace but do not label for verification'
kubectl create namespace demo-scalable
export NS=demo-scalable
echo '::endgroup::'

echo '::group:: Deploy deployment with unsigned image'
sed "s#TEST_IMAGE#${demoimage}#" ./test/testdata/policy-controller/e2e/test-deployment.yaml | kubectl apply -f -
echo '::endgroup::'

echo '::group:: Label test namespace for verification'
kubectl label namespace ${NS} policy.sigstore.dev/include=true
echo '::endgroup::'

echo '::group:: Deploy ClusterImagePolicy with keyless signing'
kubectl apply -f ./test/testdata/policy-controller/e2e/cip-keyless.yaml
# Give the policy controller a moment to update the configmap
# and pick up the change in the admission controller.
sleep 5
echo '::endgroup::'

echo '::group:: Try to scale the Deployment up - should fail'
expected_error="failed policy: image-policy-keyless: spec.template.spec.containers"
assert_error ${expected_error}
echo '::endgroup::'


echo '::group:: Try to scale the Deployment down - should work'
if ! kubectl patch -n ${NS} deployment test-deployment --type "json" -p '[{"op":"replace", "path":"/spec/replicas", "value":1}]' ; then
  echo Failed to scale down
    exit 1
fi
echo '::endgroup::'

echo '::group:: Sign demo image'
COSIGN_EXPERIMENTAL=1 cosign sign --rekor-url ${REKOR_URL} --fulcio-url ${FULCIO_URL} --force --allow-insecure-registry ${demoimage} --identity-token ${OIDC_TOKEN}
echo '::endgroup::'

echo '::group:: Verify demo image'
COSIGN_EXPERIMENTAL=1 cosign verify --rekor-url ${REKOR_URL} --allow-insecure-registry ${demoimage}
echo '::endgroup::'

echo '::group:: Try to scale the Deployment up - should work'
if ! kubectl patch -n ${NS} deployment test-deployment --type "json" -p '[{"op":"replace", "path":"/spec/replicas", "value":5}]' ; then
  echo Failed to scale up with signed image
    exit 1
fi
echo '::endgroup::'

echo '::group::' Cleanup
kubectl delete cip --all
kubectl delete ns ${NS}
echo '::endgroup::'
