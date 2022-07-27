# Examples

## Policies

### keyless-attestation-sbom-spdxjson

Source: [policies/keyless-attestation-sbom-spdxjson.yaml](./policies/keyless-attestation-sbom-spdxjson.yaml)

Assert that all images must have a "keyless"
signed SPDX SBOM (spdxjson) attestation against
the public Fulcio root.

#### How to satisfy this policy

First, use your favorite tool to generate an [SPDX](https://spdx.dev/) SBOM.

For example, use [bom](https://github.com/kubernetes-sigs/bom)
to generate an SPDX SBOM from a Go project (Kubernetes):
```
git clone --depth=1 https://github.com/kubernetes/kubernetes
bom generate -n https://kubernetes.io/ kubernetes/ --format json | tee ./spdx-sbom.json
rm -rf kubernetes/
```

Then attach it to your image (`REF`) using [cosign attest](https://github.com/sigstore/cosign/blob/main/doc/cosign_attest.md)
with the flag `--type spdxjson`, signing "keyless" against the public Fulcio root:
```
export REF="r.example.com/myapp:v0.1.0"
export COSIGN_EXPERIMENTAL=1

cosign attest --yes --type spdxjson --predicate ./spdx-sbom.json "${REF}"
```

Test your image against the policy (from root of this repo):

```
export REF="r.example.com/myapp:v0.1.0"

(set -o pipefail && make policy-tester && ./policy-tester \
  --policy=./examples/policies/keyless-attestation-sbom-spdxjson.yaml \
  --image "${REF}" | jq)
```
