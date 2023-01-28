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
kubectl create namespace demo-tsa-remote
kubectl label namespace demo-tsa-remote policy.sigstore.dev/include=true
export NS=demo-tsa-remote
echo '::endgroup::'

echo '::group:: Generate New Signing Key that we use for key-ful signing'
COSIGN_PASSWORD="" cosign generate-key-pair
echo '::endgroup::'

# Sign it with key
echo '::group:: Sign demoimage with key, and add to rekor and TSA'
export TSA_URL=`kubectl -n tsa-system get ksvc tsa -ojsonpath='{.status.url}'`
COSIGN_EXPERIMENTAL=1 COSIGN_PASSWORD="" cosign sign --key cosign.key --allow-insecure-registry --rekor-url ${REKOR_URL} --timestamp-server-url ${TSA_URL} ${demoimage}
echo '::endgroup::'

echo '::group:: Verify demoimage with cosign key and TSA'
export TSA_CERT_CHAIN=`kubectl -n tsa-system get secrets tsa-cert-chain -ojsonpath='{.data.cert-chain}'`
echo "$TSA_CERT_CHAIN" | base64 -d > tsa-cert-chain.pem
COSIGN_EXPERIMENTAL=1 cosign verify --key cosign.pub --timestamp-cert-chain tsa-cert-chain.pem --insecure-ignore-tlog --rekor-url ${REKOR_URL} --allow-insecure-registry --certificate-identity-regexp='.*'  --certificate-oidc-issuer-regexp='.*' ${demoimage}
echo '::endgroup::'

echo '::group:: Create TrustRoot that specifies TSA'
cp ./test/testdata/trustroot/e2e/with-tsa.yaml ./with-tsa.yaml.bkp
sed -i'' -e "s@TSA_CERT_CHAIN@${TSA_CERT_CHAIN}@g" ./test/testdata/trustroot/e2e/with-tsa.yaml
sed -i'' -e "s@TSA_URL@${TSA_URL}@g" ./test/testdata/trustroot/e2e/with-tsa.yaml
kubectl apply -f ./test/testdata/trustroot/e2e/with-tsa.yaml
# allow things to propagate
sleep 5
echo '::endgroup::'

echo '::group:: Create CIP that requires a keyful and includes a TSA verification'
yq '. | .spec.authorities[0].key.data |= load_str("cosign.pub")' ./test/testdata/policy-controller/e2e/cip-key-tsa.yaml | kubectl apply -f -
# Give the policy controller a moment to update the configmap
# and pick up the change in the admission controller.
sleep 5
echo '::endgroup::'

echo '::group:: test job success'
# This has now a job signed and verified via a TSA, so should pass.
export KUBECTL_SUCCESS_FILE="/tmp/kubectl.success.out"
if ! kubectl create -n ${NS} job demo --image=${demoimage} 2> ${KUBECTL_SUCCESS_FILE} ; then
  echo Failed to create job with a TSA verification
  cat ${KUBECTL_SUCCESS_FILE}
  exit 1
else
  echo Created the job with a TSA verification
fi
kubectl delete -n ${NS} job demo
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

# Sign it with key
echo '::group:: Sign demoimage2 with key, and add to rekor and TSA'
export TSA_URL=`kubectl -n tsa-system get ksvc tsa -ojsonpath='{.status.url}'`
COSIGN_EXPERIMENTAL=1 COSIGN_PASSWORD="" cosign sign --key cosign.key --allow-insecure-registry --rekor-url ${REKOR_URL} --timestamp-server-url ${TSA_URL} ${demoimage2}
echo '::endgroup::'

echo '::group:: Verify demoimage2 with cosign key and TSA'
export TSA_CERT_CHAIN=`kubectl -n tsa-system get secrets tsa-cert-chain -ojsonpath='{.data.cert-chain}'`
echo "$TSA_CERT_CHAIN" | base64 -d > tsa-cert-chain.pem
COSIGN_EXPERIMENTAL=1 cosign verify --key cosign.pub --timestamp-cert-chain tsa-cert-chain.pem --insecure-ignore-tlog --allow-insecure-registry --certificate-identity-regexp='.*'  --certificate-oidc-issuer-regexp='.*' ${demoimage2}
echo '::endgroup::'

echo '::group:: Change Certificate chain of TrustRoot to a wrong one for our TSA'
cp ./with-tsa.yaml.bkp ./test/testdata/trustroot/e2e/with-tsa.yaml
# This certificate chain belongs a different TSA server so any verification should fail
export TSA_CERT_CHAIN="LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUJ6RENDQVhLZ0F3SUJBZ0lVWFBCNWVWRWhZcVBPaEk0dE45ak4wM1ZkUW5rd0NnWUlLb1pJemowRUF3SXcKTURFT01Bd0dBMVVFQ2hNRmJHOWpZV3d4SGpBY0JnTlZCQU1URlZSbGMzUWdWRk5CSUVsdWRHVnliV1ZrYVdGMApaVEFlRncweU1qRXhNakV4TVRVNE1UaGFGdzB6TVRFeE1qRXhNakF4TVRoYU1EQXhEakFNQmdOVkJBb1RCV3h2ClkyRnNNUjR3SEFZRFZRUURFeFZVWlhOMElGUlRRU0JVYVcxbGMzUmhiWEJwYm1jd1dUQVRCZ2NxaGtqT1BRSUIKQmdncWhrak9QUU1CQndOQ0FBVEhvRUE3b05URWJDcjVxdnd6STlsN0ZJaHNqQlFnUDhGbFhEeFNDaFdYVDJZNQpMWDhQVlFYTHJFbHhNVzJ0dnk0SjQzdTJCRG9JQ1hHeW5xZ1pWMlBmbzJvd2FEQU9CZ05WSFE4QkFmOEVCQU1DCkI0QXdIUVlEVlIwT0JCWUVGQis4WEx2TTlWU3pyUmdFQiswOUZrdlhmYVM2TUI4R0ExVWRJd1FZTUJhQUZDWUIKSEc1eDVDVE9YLytueVlsanltWVZQT3ZqTUJZR0ExVWRKUUVCL3dRTU1Bb0dDQ3NHQVFVRkJ3TUlNQW9HQ0NxRwpTTTQ5QkFNQ0EwZ0FNRVVDSUFJd1IwMG5xRS96cG5OSEozY3VoWTRRZjEzTkd3anhUOTBSUWhxSjFNZlpBaUVBCm9lclFGQWVGYnZYU3VLTFdXK2lsdEh2dEsyUUF1VXZub1ZnZ0tCYzhpSTg9Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0KLS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUIwakNDQVhpZ0F3SUJBZ0lVVXgvd3NrMFNhVU5ZcUtKWEtLMlpyMmYzZlJFd0NnWUlLb1pJemowRUF3SXcKS0RFT01Bd0dBMVVFQ2hNRmJHOWpZV3d4RmpBVUJnTlZCQU1URFZSbGMzUWdWRk5CSUZKdmIzUXdIaGNOTWpJeApNVEl4TVRFMU5qRTRXaGNOTXpJeE1USXhNVEl3TVRFNFdqQXdNUTR3REFZRFZRUUtFd1ZzYjJOaGJERWVNQndHCkExVUVBeE1WVkdWemRDQlVVMEVnU1c1MFpYSnRaV1JwWVhSbE1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMEQKQVFjRFFnQUVvUysxNFNXTmUxc2hwc280cERFMEhTNjZqdmYyenlJUS9jcHRuM2pyUTAyelJYZWQ5THBWS1A3YwpJbEVXWWNSaWw0anNXUkFsMU9zVjk4eGNFTUpvaktONE1IWXdEZ1lEVlIwUEFRSC9CQVFEQWdFR01CTUdBMVVkCkpRUU1NQW9HQ0NzR0FRVUZCd01JTUE4R0ExVWRFd0VCL3dRRk1BTUJBZjh3SFFZRFZSME9CQllFRkNZQkhHNXgKNUNUT1gvK255WWxqeW1ZVlBPdmpNQjhHQTFVZEl3UVlNQmFBRkYxWEFHbW4xQXdtdFk0L0RGVWQ4RzhkTFRIMQpNQW9HQ0NxR1NNNDlCQU1DQTBnQU1FVUNJUUNoZTVTWVpsbVNWeXczczJOcDRQNE5FS1l0ODc4RGZ6M3JlRlZKCkVHemxJd0lnUEc4bHlaYXdLOWo2c3BlTHFtUy9Hei9LdjJJQ3FsSy9XOEFzNGN1OEtuRT0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQotLS0tLUJFR0lOIENFUlRJRklDQVRFLS0tLS0KTUlJQmxUQ0NBVHFnQXdJQkFnSVVQY2NwVS95TUJkNmViMzM1YlZSOTZwTGZNQWN3Q2dZSUtvWkl6ajBFQXdJdwpLREVPTUF3R0ExVUVDaE1GYkc5allXd3hGakFVQmdOVkJBTVREVlJsYzNRZ1ZGTkJJRkp2YjNRd0hoY05Nakl4Ck1USXhNVEUxTmpFNFdoY05Nekl4TVRJeE1USXdNVEU0V2pBb01RNHdEQVlEVlFRS0V3VnNiMk5oYkRFV01CUUcKQTFVRUF4TU5WR1Z6ZENCVVUwRWdVbTl2ZERCWk1CTUdCeXFHU000OUFnRUdDQ3FHU000OUF3RUhBMElBQklUWgpqZnVhTGJXbjloYjhtNVVabmtrcUs5K3dQam92b0F3VCtPQWRTK0kzZlptTFRnamdoMW8vUHhtb0UvT2RuOUtOCmtxcnVKWkJuaWQwb0VVT3BwWE9qUWpCQU1BNEdBMVVkRHdFQi93UUVBd0lCQmpBUEJnTlZIUk1CQWY4RUJUQUQKQVFIL01CMEdBMVVkRGdRV0JCUmRWd0JwcDlRTUpyV09Qd3hWSGZCdkhTMHg5VEFLQmdncWhrak9QUVFEQWdOSgpBREJHQWlFQWhFdW9xQ2JaRDA5bmx2WjNtcFJiR0paZFg0Nm1rUFUrVFFpUklFT2l5NGdDSVFEakRBWDdxT0x0Cm5RVEVrRGcwcklBU0hqaVVNTk5tRVFqTlZmaDlDMEx3OXc9PQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0t"
sed -i'' -e "s@TSA_CERT_CHAIN@${TSA_CERT_CHAIN}@g" ./test/testdata/trustroot/e2e/with-tsa.yaml
sed -i'' -e "s@TSA_URL@${TSA_URL}@g" ./test/testdata/trustroot/e2e/with-tsa.yaml
kubectl apply -f ./test/testdata/trustroot/e2e/with-tsa.yaml
# allow things to propagate
sleep 10
echo '::endgroup::'

# We did sign this, but should fail due to a different certificate chain for the TSA verification
echo '::group:: test job rejection with TSA using a different cert-chain'
if kubectl create -n ${NS} job demo2 --image=${demoimage2} ; then
  echo Failed to block Job creation when TSA verification fails!
  exit 1
else
  echo Successfully blocked Job creation with TSA using a different certificate chain
fi
echo '::endgroup::'

echo '::group::' Cleanup
kubectl delete cip --all
kubectl delete trustroot --all
kubectl delete ns ${NS}
echo '::endgroup::'
