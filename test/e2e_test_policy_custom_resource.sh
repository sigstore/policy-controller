#!/usr/bin/env bash
#
# Copyright 2024 The Sigstore Authors.
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

# Variables
export CUSTOM_RESOURCE="Pods,ReplicaSets"
export NS=custom-resource-test
export TIMESTAMP="TIMESTAMP"

# Helper function to validate webhook configuration
assert_webhook_configuration() {
  local webhook_name=$1
  local resource=$2

  echo "Validating ${webhook_name} for resource ${resource}"
  kubectl get ${webhook_name} -o yaml | grep -q "resources:.*${resource}" || {
    echo "Resource ${resource} not found in ${webhook_name}"
    exit 1
  }
  echo "Resource ${resource} found in ${webhook_name}"
}

echo '::group:: Create and label namespace for testing'
kubectl create namespace ${NS}
kubectl label namespace ${NS} policy.sigstore.dev/include=true
echo '::endgroup::'

echo '::group:: Validate webhook configurations'
sleep 5  # Allow webhook configurations to propagate

for resource in Pods ReplicaSets; do
  assert_webhook_configuration "MutatingWebhookConfiguration" "${resource}"
  assert_webhook_configuration "ValidatingWebhookConfiguration" "${resource}"
done

# Ensure a non-monitored resource is NOT included
if kubectl get MutatingWebhookConfiguration -o yaml | grep -q "resources:.*DaemonSet"; then
  echo "DaemonSet should not be included in MutatingWebhookConfiguration"
  exit 1
else
  echo "DaemonSet correctly excluded from MutatingWebhookConfiguration"
fi
echo '::endgroup::'

echo '::group:: Cleanup'
kubectl delete ns ${NS}
echo '::endgroup::'

echo "Custom resource flag test completed successfully!"
