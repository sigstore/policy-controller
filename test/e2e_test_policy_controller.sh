#!/usr/bin/env bash
#
# Copyright 2021 The Sigstore Authors.
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


echo '::group:: publish test image'
DIGEST=$(ko publish -B ./cmd/sample)
cat > pod.yaml <<EOF
apiVersion: v1
kind: Pod
metadata:
  generateName: pod-test-
spec:
  restartPolicy: Never
  containers:
  - name: sample
    image: $KO_DOCKER_REPO/sample
EOF
cat > distroless-pod.yaml <<EOF
apiVersion: v1
kind: Pod
metadata:
  generateName: pod-test-
spec:
  restartPolicy: Never
  containers:
  - name: sample
    image: ghcr.io/distroless/alpine-base:latest
    command: [/bin/sh, -c]
    args:
    - |
      echo Testing Fulcio verification
EOF
cat > job.yaml <<EOF
apiVersion: batch/v1
kind: Job
metadata:
  generateName: job-test-
spec:
  template:
    spec:
      restartPolicy: Never
      containers:
        - name: sample
          image: $KO_DOCKER_REPO/sample
EOF

cat > cronjob.yaml <<EOF
apiVersion: batch/v1
kind: CronJob
metadata:
  generateName: cronjob-test-
spec:
  schedule: "* * * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: sample
            image: $KO_DOCKER_REPO/sample
          restartPolicy: Never
EOF
echo '::endgroup::'

echo '::group:: enable verification'
kubectl label namespace default --overwrite policy.sigstore.dev/include=true
echo '::endgroup::'

echo '::group:: test pod rejection (no policy applied yet, and default deny)'
# Should fail, because no matching policy and default deny
if kubectl create -f distroless-pod.yaml ; then
  echo Failed to block Pod signed by Fulcio without any matching policy.
  exit 1
else
  echo Successfully blocked Pod signed by Fulcio without any matching policy.
fi
echo '::endgroup::'

echo '::group:: test job success (no policy applied yet, and default deny)'
# Should fail, because no matching policy and default deny
if kubectl create -f job.yaml ; then
  echo Failed to block Job in namespace without any matching policy!
  exit 1
else
  echo Successfully blocked Job in namespace without any matching policy.
fi
echo '::endgroup::'

echo '::group:: test cronjob success (no policy applied yet, and default deny)'
# Should fail, because no matching policy and default deny
if kubectl create -f cronjob.yaml ; then
  echo Failed to block CronJob in namespace without any matching policy!
  exit 1
else
  echo Successfully blocked CronJob in namespace without any matching policy.
fi
echo '::endgroup::'

echo '::group:: Change no-match policy to allow'
kubectl patch configmap/config-policy-controller \
  --namespace cosign-system \
  --type merge \
  --patch '{"data":{"no-match-policy":"allow"}}'
# allow for propagation
sleep 5
echo '::endgroup::'

echo '::group:: test pod success (no policy applied yet, default allow)'
# This time it should succeed!
if ! kubectl create -f distroless-pod.yaml ; then
  echo Failed to create Pod signed by Fulcio without any matching policy!
  exit 1
else
  echo Successfully created Pod signed by Fulcio without any matching policy.
fi
echo '::endgroup::'

echo '::group:: test job success (no policy applied yet, default allow)'
# This time it should succeed!
if ! kubectl create -f job.yaml ; then
  echo Failed to create Job in namespace without label!
  exit 1
else
  echo Successfully created Job in namespace without label.
fi
echo '::endgroup::'

echo '::group:: test cronjob success (no policy applied yet, default allow)'
# This time it should succeed!
if ! kubectl create -f cronjob.yaml ; then
  echo Failed to create CronJob in namespace without label!
  exit 1
else
  echo Successfully created CronJob in namespace without label.
fi
echo '::endgroup::'

echo '::group:: disable verification'
kubectl label namespace default --overwrite policy.sigstore.dev/include=false
echo '::endgroup::'

echo '::group:: test pod success (after disabling verification in namespace)'
# This time it should succeed!
if ! kubectl create -f pod.yaml ; then
  echo Failed to create Pod in namespace without label!
  exit 1
else
  echo Successfully created Pod in namespace without label.
fi
echo '::endgroup::'

echo '::group:: test job success (after disabling verification in namespace)'
# This time it should succeed!
if ! kubectl create -f job.yaml ; then
  echo Failed to create Job in namespace without label!
  exit 1
else
  echo Successfully created Job in namespace without label.
fi
echo '::endgroup::'

echo '::group:: test cronjob success (after disabling verification in namespace)'
# This time it should succeed!
if ! kubectl create -f cronjob.yaml ; then
  echo Failed to create CronJob in namespace without label!
  exit 1
else
  echo Successfully created CronJob in namespace without label.
fi
echo '::endgroup::'
