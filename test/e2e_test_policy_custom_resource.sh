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
export CUSTOM_RESOURCE="DaemonSet,ReplicaSets"
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

# Helper function to check if an image uses a tag
assert_image_tag() {
  local pod_name=$1
  local container_name=$2

  echo "Checking that ${pod_name}/${container_name} uses a tag, not a digest"
  image=$(kubectl get pod "${pod_name}" -n "${NS}" -o=jsonpath="{.spec.containers[?(@.name=='${container_name}')].image}")
  if [[ "${image}" =~ @sha256:[a-f0-9]{64} ]]; then
    echo "Image ${image} is using a digest, which is not allowed"
    exit 1
  else
    echo "Image ${image} is correctly using a tag"
  fi
}

# Step 1: Create namespace
echo '::group:: Create and label namespace for testing'
kubectl create namespace ${NS}
kubectl label namespace ${NS} policy.sigstore.dev/include=true
echo '::endgroup::'

# Step 2: Deploy Policy Controller with custom-resource flag
echo '::group:: Deploy Policy Controller with custom-resource flag'
KO_DOCKER_REPO=${KO_DOCKER_REPO} ko apply -f ./deploy/manifests.yaml \
  --set-string policyController.customResource=${CUSTOM_RESOURCE}
echo '::endgroup::'

# Step 3: Validate webhook configurations
echo '::group:: Validate webhook configurations'
sleep 5  # Allow webhook configurations to propagate

for resource in DaemonSet ReplicaSets; do
  assert_webhook_configuration "MutatingWebhookConfiguration" "${resource}"
  assert_webhook_configuration "ValidatingWebhookConfiguration" "${resource}"
done

# Ensure a non-monitored resource is NOT included
if kubectl get MutatingWebhookConfiguration -o yaml | grep -q "resources:.*Pods"; then
  echo "Pods should not be included in MutatingWebhookConfiguration"
  exit 1
else
  echo "Pods correctly excluded from MutatingWebhookConfiguration"
fi
echo '::endgroup::'

# Step 4: Deploy sandbox and check for image tag usage
echo '::group:: Deploy sandbox and check image tags'
cat <<EOF | kubectl apply -n ${NS} -f -
apiVersion: v1
kind: Pod
metadata:
  name: sandbox-pod
spec:
  containers:
  - name: sandbox-container
    image: nginx:1.23.2
    command: ["sleep"]
    args: ["3600"]
EOF

# Wait for the pod to be ready
kubectl wait --for=condition=Ready pod/sandbox-pod -n ${NS} --timeout=60s

# Validate that the image uses a tag
assert_image_tag "sandbox-pod" "sandbox-container"
echo '::endgroup::'

# Step 5: Clean up
echo '::group:: Cleanup'
kubectl delete ns ${NS}
echo '::endgroup::'

echo "Custom resource flag and sandbox image tag tests completed successfully!"
