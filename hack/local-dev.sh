#!/bin/bash

# Copyright 2022 The Sigstore Authors
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

# The script can take two optional arguments:
# 1. cluster-name - default value is 'policy-controller-demo'
# 2. ko-docker-repo - if no value is provided, the local Kind registry is used
#

LOCAL_REGISTRY_NAME="registry.local"
LOCAL_REGISTRY_PORT=5001
K8S_VERSION="1.24.7"
KIND_IMAGE_SHA="sha256:577c630ce8e509131eab1aea12c022190978dd2f745aac5eb1fe65c0807eb315"
KIND_IMAGE=kindest/node:${K8S_VERSION}@${KIND_IMAGE_SHA}

if [ -z "$1" ]
then
  echo "cluster-name argument not provided, using default name 'policy-controller-demo'"
  CLUSTER_NAME="policy-controller-demo"
else
  CLUSTER_NAME="$1"
fi

if [ -z "$2" ]
then
  echo "ko-docker-repo arugment not provided, the local Kind registry will be used"
  USE_LOCAL_REGISTRY=true
  export KO_DOCKER_REPO="registry.local:5001/sigstore"
else
  USE_LOCAL_REGISTRY=false
  export KO_DOCKER_REPO="$2"
fi

cat > kind.yaml <<EOF
apiVersion: kind.x-k8s.io/v1alpha4
kind: Cluster
nodes:
- role: control-plane
  image: "${KIND_IMAGE}"
- role: worker
  image: "${KIND_IMAGE}"

# Configure registry for KinD.
containerdConfigPatches:
- |-
  [plugins."io.containerd.grpc.v1.cri".registry.mirrors."$LOCAL_REGISTRY_NAME:$LOCAL_REGISTRY_PORT"]
    endpoint = ["http://$LOCAL_REGISTRY_NAME:$LOCAL_REGISTRY_PORT"]
# This is needed in order to support projected volumes with service account tokens.
# See: https://kubernetes.slack.com/archives/CEKK1KTN2/p1600268272383600
kubeadmConfigPatches:
  - |
    apiVersion: kubeadm.k8s.io/v1beta2
    kind: ClusterConfiguration
    metadata:
      name: config
    apiServer:
      extraArgs:
        "service-account-issuer": "https://kubernetes.default.svc"
        "service-account-key-file": "/etc/kubernetes/pki/sa.pub"
        "service-account-signing-key-file": "/etc/kubernetes/pki/sa.key"
        "service-account-api-audiences": "api,spire-server"
        "service-account-jwks-uri": "https://kubernetes.default.svc/openid/v1/jwks"
    networking:
      dnsDomain: "cluster.local"
EOF

echo "Creating Kind cluster $CLUSTER_NAME"
kind create cluster --config kind.yaml --name $CLUSTER_NAME

if [ $USE_LOCAL_REGISTRY = true ];
then
    echo "Starting local registry $LOCAL_REGISTRY_NAME..."
    docker run -d --restart=always -p "127.0.0.1:$LOCAL_REGISTRY_PORT:$LOCAL_REGISTRY_PORT" --name $LOCAL_REGISTRY_NAME -e "REGISTRY_HTTP_ADDR=0.0.0.0:$LOCAL_REGISTRY_PORT" registry:2

	# Connect the registry to the KinD network.
	docker network connect kind $LOCAL_REGISTRY_NAME

    if ! grep -q "$LOCAL_REGISTRY_NAME" /etc/hosts; then
        # Make the $LOCAL_REGISTRY_NAME -> 127.0.0.1, to tell `ko` to publish to
        # local reigstry, even when pushing $LOCAL_REGISTRY_NAME:$LOCAL_REGISTRY_PORT/some/image
        echo "127.0.0.1 $LOCAL_REGISTRY_NAME" | sudo tee -a /etc/hosts
    fi
fi

GIT_HASH=$(git rev-parse HEAD)
GIT_VERSION=$(git describe --tags --always --dirty)

CONFIG_FILES=$(find ../config -name "*.yaml" ! -name 'kustomization.yaml' | sort)

for i in ${CONFIG_FILES[@]}
do
    ko apply -f $i
done
