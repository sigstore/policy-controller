#!/bin/bash

# Copyright 2023 The Sigstore Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# The script accepts the following optional arguments:
# 1. cluster-name - default value is 'policy-controller-demo'
# 2. k8s-version - default value is 'v1.24.x'
# 3. registry-url - if no value is provided, the local Kind registry is used
#

set -o errexit

CLUSTER_NAME="policy-controller-demo"
K8S_VERSION="v1.26.x"
KIND_VERSION="v0.15.0"
LOCAL_REGISTRY_NAME="registry.local"
LOCAL_REGISTRY_PORT=5001
REGISTRY_NAME=$LOCAL_REGISTRY_NAME
REGISTRY_PORT=$LOCAL_REGISTRY_PORT

while [[ $# -ne 0 ]]; do
  parameter="$1"
  case "${parameter}" in
    --cluster-name)
      shift
      CLUSTER_NAME="$1"
      ;;
    --k8s-version)
      shift
      K8S_VERSION="$1"
      ;;
    --registry-url)
      shift
      REGISTRY_NAME="$(echo "$1" | cut -d':' -f 1)"
      REGISTRY_PORT="$(echo "$1" | cut -d':' -f 2)"
      ;;
    *) echo "unknown option ${parameter}"; exit 1 ;;
  esac
  shift
done

if [ $REGISTRY_NAME = $LOCAL_REGISTRY_NAME ];
then
  export KO_DOCKER_REPO="$LOCAL_REGISTRY_NAME:$LOCAL_REGISTRY_PORT/sigstore"
else
  export KO_DOCKER_REPO="$REGISTRY_NAME"
fi

# Map the Kind image version to this version of Kind and K8s
case ${K8S_VERSION} in
  v1.23.x)
    K8S_VERSION="1.23.13"
    KIND_IMAGE_SHA="sha256:ef453bb7c79f0e3caba88d2067d4196f427794086a7d0df8df4f019d5e336b61"
    KIND_IMAGE="kindest/node:v${K8S_VERSION}@${KIND_IMAGE_SHA}"
    ;;
  v1.24.x)
    K8S_VERSION="1.24.7"
    KIND_IMAGE_SHA="sha256:577c630ce8e509131eab1aea12c022190978dd2f745aac5eb1fe65c0807eb315"
    KIND_IMAGE=kindest/node:${K8S_VERSION}@${KIND_IMAGE_SHA}
    ;;
  v1.25.x)
    K8S_VERSION="1.25.3"
    KIND_IMAGE_SHA="sha256:f52781bc0d7a19fb6c405c2af83abfeb311f130707a0e219175677e366cc45d1"
    KIND_IMAGE=kindest/node:${K8S_VERSION}@${KIND_IMAGE_SHA}
    ;;
  v1.26.x)
    K8S_VERSION="1.26.0"
    KIND_IMAGE_SHA="sha256:691e24bd2417609db7e589e1a479b902d2e209892a10ce375fab60a8407c7352"
    KIND_IMAGE=kindest/node:${K8S_VERSION}@${KIND_IMAGE_SHA}
    ;;
  *) echo "Unsupported version: ${K8S_VERSION}"; exit 1 ;;
esac

# Create a basic Kind cluster configuration
cat > kind.yaml <<EOF
  apiVersion: kind.x-k8s.io/v1alpha4
  kind: Cluster
  name: "${CLUSTER_NAME}"
  nodes:
  - role: control-plane
    image: "${KIND_IMAGE}"
  # Configure registry for KinD.
  containerdConfigPatches:
  - |-
    [plugins."io.containerd.grpc.v1.cri".registry.mirrors."$REGISTRY_NAME:$REGISTRY_PORT"]
      endpoint = ["http://$REGISTRY_NAME:$REGISTRY_PORT"]
EOF

if [ $KO_DOCKER_REPO = "$LOCAL_REGISTRY_NAME:$LOCAL_REGISTRY_PORT/sigstore" ];
then
  echo "Creating Kind cluster $CLUSTER_NAME with local registry..."
  kind create cluster --config kind.yaml

  echo "Starting local registry $LOCAL_REGISTRY_NAME..."
  docker run -d --restart=always -p "127.0.0.1:$LOCAL_REGISTRY_PORT:$LOCAL_REGISTRY_PORT" --name $LOCAL_REGISTRY_NAME -e "REGISTRY_HTTP_ADDR=0.0.0.0:$LOCAL_REGISTRY_PORT" registry:2

	# Connect the registry to the KinD network.
	docker network connect kind $LOCAL_REGISTRY_NAME

  if ! grep -q "$LOCAL_REGISTRY_NAME" /etc/hosts; then
    # Make the $LOCAL_REGISTRY_NAME -> 127.0.0.1, to tell `ko` to publish to
    # local reigstry, even when pushing $LOCAL_REGISTRY_NAME:$LOCAL_REGISTRY_PORT/some/image
    echo "127.0.0.1 $LOCAL_REGISTRY_NAME" | sudo tee -a /etc/hosts
  fi
else
  echo "Creating Kind cluster $CLUSTER_NAME with provided registry..."
  kind create cluster --config kind.yaml
fi

export GIT_HASH=$(git rev-parse HEAD)
export GIT_VERSION=$(git describe --tags --always --dirty)

CONFIG_FILES=$(find config -name "*.yaml" ! -name 'kustomization.yaml' | sort)

for i in ${CONFIG_FILES[@]}
do
  ko apply -f $i
done
