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

# E2E test for the --resource-names flag functionality.
#
# This test validates selective resource monitoring by configuring the policy
# controller to monitor only ReplicaSets and DaemonSets, then verifying:
# 1. Unmonitored resources (Pods, Deployments) are allowed without policy checks
# 2. Monitored resources (ReplicaSets, DaemonSets) are properly validated
# 3. Signed images are allowed for monitored resources

set -ex

if [[ -z "${KO_DOCKER_REPO}" ]]; then
  echo "Must specify env variable KO_DOCKER_REPO"
  exit 1
fi

# Variables
export NS=demo-resource-names
export demoimage="ghcr.io/sigstore/timestamp-server@sha256:dcf2f3a640bfb0a5d17aabafb34b407fe4403363c715718ab305a62b3606540d"

echo "=========================================="
echo "Testing custom resource monitoring"
echo "=========================================="

# Step 1: Deploy policy controller with ONLY ReplicaSets and DaemonSets monitored
echo '::group:: Deploy policy-controller with custom resources (replicasets,daemonsets only)'
kubectl apply -f <(kustomize build ./test/kustomize-resource-names)
kubectl rollout status --timeout 5m --namespace cosign-system deployments/webhook
echo '::endgroup::'

# Step 2: Verify webhook configuration
echo '::group:: Verify webhook is configured for custom resources'
# Wait for webhook configuration to be updated with custom resources
echo "Waiting for webhook configuration to be updated..."
for i in {1..30}; do
  if kubectl get validatingwebhookconfiguration policy.sigstore.dev -o yaml | grep -q "replicasets"; then
    echo "replicasets found in webhook configuration"
    break
  fi
  echo "Attempt $i/30: Waiting for webhook configuration update..."
  sleep 2
done

# Check that webhook rules include replicasets and daemonsets
kubectl get validatingwebhookconfiguration policy.sigstore.dev -o yaml | grep -q "replicasets" || {
  echo "ERROR: replicasets not found in webhook configuration"
  kubectl get validatingwebhookconfiguration policy.sigstore.dev -o yaml
  exit 1
}
kubectl get validatingwebhookconfiguration policy.sigstore.dev -o yaml | grep -q "daemonsets" || {
  echo "ERROR: daemonsets not found in webhook configuration"
  kubectl get validatingwebhookconfiguration policy.sigstore.dev -o yaml
  exit 1
}
echo "Webhook correctly configured for ReplicaSet and DaemonSet"
echo '::endgroup::'

# Step 3: Create test namespace
echo '::group:: Create and label test namespace'
kubectl create namespace ${NS}
kubectl label namespace ${NS} policy.sigstore.dev/include=true
echo '::endgroup::'

# Step 4: Deploy ClusterImagePolicy
echo '::group:: Deploy ClusterImagePolicy requiring signatures'
cat <<EOF | kubectl apply -f -
apiVersion: policy.sigstore.dev/v1beta1
kind: ClusterImagePolicy
metadata:
  name: image-policy-resource-names
spec:
  images:
  - glob: "**"
  authorities:
  - keyless:
      url: https://fulcio.sigstore.dev
      identities:
      - issuerRegExp: https://token.actions.githubusercontent.com
        subjectRegExp: https://github.com/sigstore/timestamp-.*/.github/workflows/.*
EOF
sleep 5
echo '::endgroup::'

# Step 5: Test that Pods are NOT monitored
# Unmonitored resources should be allowed without policy checks
echo '::group:: Test that Pods are NOT monitored'
if ! cat <<EOF | kubectl apply -f -; then
apiVersion: v1
kind: Pod
metadata:
  name: test-pod-unmonitored
  namespace: ${NS}
spec:
  containers:
  - name: test
    image: busybox:latest
    command: ["sleep", "3600"]
EOF
  echo "ERROR: Pod should be allowed since Pods are not in monitored resources"
  exit 1
fi
echo "SUCCESS: Pod was allowed (not monitored)"
kubectl delete pod test-pod-unmonitored -n ${NS} --ignore-not-found=true
echo '::endgroup::'

# Step 6: Test that Deployments are NOT monitored
echo '::group:: Test that Deployments are NOT monitored'
if ! cat <<EOF | kubectl apply -f -; then
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-deployment-unmonitored
  namespace: ${NS}
spec:
  replicas: 1
  selector:
    matchLabels:
      app: test-unmonitored
  template:
    metadata:
      labels:
        app: test-unmonitored
    spec:
      containers:
      - name: test
        image: busybox:latest
        command: ["sleep", "3600"]
EOF
  echo "ERROR: Deployment should be allowed since Deployments are not in monitored resources"
  exit 1
fi
echo "SUCCESS: Deployment was allowed (not monitored)"
kubectl delete deployment test-deployment-unmonitored -n ${NS} --ignore-not-found=true
echo '::endgroup::'

# Step 7: Test that ReplicaSets ARE monitored
# Monitored resources should be validated and blocked if policy is violated
echo '::group:: Test that ReplicaSets ARE monitored'
if cat <<EOF | kubectl apply -f -; then
apiVersion: apps/v1
kind: ReplicaSet
metadata:
  name: test-replicaset-monitored
  namespace: ${NS}
spec:
  replicas: 1
  selector:
    matchLabels:
      app: test-monitored
  template:
    metadata:
      labels:
        app: test-monitored
    spec:
      containers:
      - name: test
        image: busybox:latest
        command: ["sleep", "3600"]
EOF
  echo "ERROR: ReplicaSet should be blocked since ReplicaSets are monitored and image is not signed"
  kubectl delete replicaset test-replicaset-monitored -n ${NS} --ignore-not-found=true
  exit 1
fi
echo "SUCCESS: ReplicaSet was blocked (monitored)"
echo '::endgroup::'

# Step 8: Test that DaemonSets ARE monitored
echo '::group:: Test that DaemonSets ARE monitored'
if cat <<EOF | kubectl apply -f -; then
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: test-daemonset-monitored
  namespace: ${NS}
spec:
  selector:
    matchLabels:
      app: test-monitored-ds
  template:
    metadata:
      labels:
        app: test-monitored-ds
    spec:
      containers:
      - name: test
        image: busybox:latest
        command: ["sleep", "3600"]
EOF
  echo "ERROR: DaemonSet should be blocked since DaemonSets are monitored and image is not signed"
  kubectl delete daemonset test-daemonset-monitored -n ${NS} --ignore-not-found=true
  exit 1
fi
echo "SUCCESS: DaemonSet was blocked (monitored)"
echo '::endgroup::'

# Step 9: Test with properly signed image
# Verify that policy validation logic works correctly for compliant images
echo '::group:: Test that signed images are allowed for monitored resources'
if ! cat <<EOF | kubectl apply -f -; then
apiVersion: apps/v1
kind: ReplicaSet
metadata:
  name: test-replicaset-signed
  namespace: ${NS}
spec:
  replicas: 1
  selector:
    matchLabels:
      app: test-signed
  template:
    metadata:
      labels:
        app: test-signed
    spec:
      containers:
      - name: test
        image: ${demoimage}
EOF
  echo "ERROR: ReplicaSet with signed image should be allowed"
  exit 1
fi
echo "SUCCESS: ReplicaSet with signed image was allowed"
kubectl delete replicaset test-replicaset-signed -n ${NS} --ignore-not-found=true
echo '::endgroup::'

echo "=========================================="
echo "All custom resource tests passed!"
echo "=========================================="

# Cleanup
kubectl delete namespace ${NS} --ignore-not-found=true
kubectl delete clusterimagepolicy image-policy-resource-names --ignore-not-found=true
