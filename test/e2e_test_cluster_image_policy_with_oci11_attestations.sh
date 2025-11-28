#!/usr/bin/env bash
#
# Copyright 2025 The Sigstore Authors.
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

# This test validates that the policy controller can discover and verify
# attestations stored using the OCI 1.1 referrers API (as opposed to the
# legacy tag-based discovery). Google Cloud Build stores attestations this way.

set -ex

# Use a public image with OCI 1.1 attestations from Google Cloud Build
# This image has attestations discoverable via the OCI 1.1 referrers API
export TEST_IMAGE="us-docker.pkg.dev/cloudrun/container/hello@sha256:ee5d02305108fd8d65a8299a26cf01b6f976986fd04062e31280f97f21a91e3d"

# Namespace for testing
export NS="demo-oci11-attest"

echo '::group:: Create test namespace'
kubectl create namespace ${NS}
echo '::endgroup::'

echo '::group:: Enable OCI 1.1 support in policy controller'
kubectl patch configmap/config-policy-controller \
  --namespace cosign-system \
  --type merge \
  --patch '{"data":{"enable-oci11":"true"}}'
# Allow for propagation
sleep 5
echo '::endgroup::'

echo '::group:: Create ClusterImagePolicy for OCI 1.1 attestations'
# This policy uses a static key (Google Cloud Build public key) to verify
# attestations discoverable via OCI 1.1 referrers API
kubectl apply -f - <<EOF
apiVersion: policy.sigstore.dev/v1alpha1
kind: ClusterImagePolicy
metadata:
  name: oci11-attestation-policy
spec:
  images:
  - glob: "us-docker.pkg.dev/cloudrun/container/**"
  authorities:
  - name: google-cloud-build-key
    key:
      data: |
        -----BEGIN PUBLIC KEY-----
        MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEg9KII7kzr/30HBluf00y9WwtMFkE
        qc3oCcFVH3QJ37IBLUv/MUApbnNHFfD75ayJ/a0F45xa+MLv5zoep+GxsA==
        -----END PUBLIC KEY-----
    attestations:
    - name: require-provenance
      predicateType: https://slsa.dev/provenance/v1
      policy:
        type: cue
        data: |
          predicateType: "https://slsa.dev/provenance/v1"
EOF
echo '::endgroup::'

# Allow time for the policy to be picked up
sleep 5

echo '::group:: Test: Create pod with OCI 1.1 attestations (should succeed)'
kubectl run -n ${NS} oci11-test \
  --image=${TEST_IMAGE} \
  --restart=Never \
  --command -- /hello

# Wait for pod to be admitted
sleep 3

# Check if pod was created successfully
if ! kubectl get pod -n ${NS} oci11-test; then
  echo "FAIL: Pod with OCI 1.1 attestations was not created"
  kubectl describe pod -n ${NS} oci11-test || true
  exit 1
else
  echo "SUCCESS: Pod with OCI 1.1 attestations was created successfully"
fi
echo '::endgroup::'

echo '::group:: Cleanup'
kubectl delete pod -n ${NS} oci11-test --ignore-not-found=true
kubectl delete clusterimagepolicy oci11-attestation-policy --ignore-not-found=true
kubectl delete namespace ${NS} --ignore-not-found=true

# Reset config to default
kubectl patch configmap/config-policy-controller \
  --namespace cosign-system \
  --type merge \
  --patch '{"data":{"enable-oci11":"false"}}'
echo '::endgroup::'

echo "OCI 1.1 attestation test PASSED"

