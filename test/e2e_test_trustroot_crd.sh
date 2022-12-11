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

set -o errexit
set -o nounset
set -o pipefail

# This script will validate an e2e for given TrustRoot resources and validate
# that they get reconciled correctly into the ConfigMap. For now we only
# validate the keys/certs but we can add more tests. Reasoning being that the
# certs/keys are the trickiest (I think) so let's start there.
# The golden files live in the ./test/testdata/trustroot/golden where
# rekor.pem is the public key for the TLog[0].PublicKey
# ctfe.pem is the public key for the CTLog[0].PublicKey
# fulcio.crt.pem is the certchain for the CertificateAuthority[0].CertChain
# tsa.crt.pem is the certchain for the TimeStampAuthorities[0].CertChain
# So we diff against those.
echo '::group:: Create a TrustRoot with bring your own keys:'
kubectl create -f ./test/testdata/trustroot/valid/valid-sigstore-keys.yaml
# Allow for changes to propagate to ConfigMap
sleep 5
echo '::endgroup::'

echo '::group:: Validating the configmap entries'
echo "Validating Fulcio entry"
kubectl -n cosign-system get cm config-sigstore-keys -ojsonpath='{.data.bring-your-own-sigstore-keys}' | yq '.certificateAuthorities[0].certChain' | base64 -d > ./got.fulcio.pem
diff ./got.fulcio.pem ./test/testdata/trustroot/golden/fulcio.crt.pem

echo "Validating TSA entry"
kubectl -n cosign-system get cm config-sigstore-keys -ojsonpath='{.data.bring-your-own-sigstore-keys}' | yq '.timestampAuthorities[0].certChain' | base64 -d > ./got.tsa.pem
diff ./got.tsa.pem ./test/testdata/trustroot/golden/tsa.crt.pem

echo "Validating Rekor entry"
kubectl -n cosign-system get cm config-sigstore-keys -ojsonpath='{.data.bring-your-own-sigstore-keys}' | yq '.tLogs[0].publicKey' | base64 -d > ./got.rekor.pem
diff ./got.rekor.pem ./test/testdata/trustroot/golden/rekor.pem

echo "Validating CTLog entry"
kubectl -n cosign-system get cm config-sigstore-keys -ojsonpath='{.data.bring-your-own-sigstore-keys}' | yq '.ctLogs[0].publicKey' | base64 -d > ./got.ctfe.pem
diff ./got.ctfe.pem ./test/testdata/trustroot/golden/ctfe.pem

kubectl delete -f ./test/testdata/trustroot/valid/valid-sigstore-keys.yaml
echo '::endgroup::'
