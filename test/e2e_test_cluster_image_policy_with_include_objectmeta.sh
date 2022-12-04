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


#set -ex
set -e

# This is a timestamp server that we just use for testing evaluating CIP level
# policy validations.
export demoimage="ghcr.io/sigstore/timestamp-server@sha256:dcf2f3a640bfb0a5d17aabafb34b407fe4403363c715718ab305a62b3606540d"

# To simplify testing failures, use this function to execute a kubectl to create
# our pod and verify that the failure is expected. Note that this sets a label
# that we expect to fail
assert_error() {
  local KUBECTL_OUT_FILE="/tmp/kubectl.failure.out"
  match="$@"
  echo looking for ${match}
  kubectl delete pod pod-that-fails -n ${NS} --ignore-not-found=true
  if kubectl run -n ${NS} -l="foo=bar" pod-that-fails --image=${demoimage} 2> ${KUBECTL_OUT_FILE} ; then
    echo Failed to block expected Pod failure!
    exit 1
  else
    echo Successfully blocked Pod creation with expected error: "${match}"
    if ! grep -q "${match}" ${KUBECTL_OUT_FILE} ; then
      echo Did not get expected failure message, wanted "${match}", got
      cat ${KUBECTL_OUT_FILE}
      exit 1
    fi
  fi
}

echo '::group:: Create test namespace and label for verification'
kubectl create namespace demo-include-objectmeta
kubectl label namespace demo-include-objectmeta policy.sigstore.dev/include=true
export NS=demo-include-objectmeta
echo '::endgroup::'

# Note that we put this in a for loop to make sure the webhook is actually
# up and running before proceeding with the tests.
echo '::group:: Deploy ClusterImagePolicy with label that should fail'
for i in {1..10}
do
  if kubectl apply -f ./test/testdata/policy-controller/e2e/cip-include-objectmeta-fails.yaml ; then
    echo successfully applied failing CIP
    break
  fi
  if [ "$i" == 10 ]; then
    echo failed to apply failing CIP
    exit 1
  fi
  echo failed to apply failing CIP. Attempt numer "$i", retrying
  sleep 2
done
# allow things to propagate
sleep 5
echo '::endgroup::'

echo '::group:: validate failure '
expected_error='failed evaluating cue policy for ClusterImagePolicy: failed to evaluate the policy with error: objectMeta.labels.foo: conflicting values "bar" and "non-bar"'
assert_error ${expected_error}
echo '::endgroup::'

echo '::group:: Remove failing ClusterImagePolicy and create one that passes'
kubectl delete -f ./test/testdata/policy-controller/e2e/cip-include-objectmeta-fails.yaml
kubectl apply -f ./test/testdata/policy-controller/e2e/cip-include-objectmeta.yaml
# allow things to propagate
sleep 5
echo '::endgroup::'

echo '::group:: test job success'
# This one should pass since the label is what we specified in the CIP
# policy.
if ! kubectl run -n ${NS} -l="foo=bar" demo --image=${demoimage} ; then
  echo Failed to create Pod in namespace with valid CIP policy!
  exit 1
else
  echo Succcessfully created Pod with correct labels
fi
echo '::endgroup::'

echo '::group::' Cleanup
kubectl delete cip --all
kubectl delete ns ${NS}
echo '::endgroup::'

