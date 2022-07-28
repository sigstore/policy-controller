# Examples

*Note: adding a new example here? Make sure to add test
for it in
[`../.github/workflows/policy-tester-examples.yml`](../.github/workflows/policy-tester-examples.yml).*

## Prerequisites

Make sure that the `policy-tester` CLI
is built.

At the root of this repo, run the following:
```
make policy-tester
```

## Example Policies

### keyless-attestation-sbom-spdxjson

Source: [policies/keyless-attestation-sbom-spdxjson.yaml](./policies/keyless-attestation-sbom-spdxjson.yaml)

Assert that all images must have a "keyless"
signed SPDX SBOM (spdxjson) attestation against
the public Fulcio root.

#### How to satisfy this policy

First, use your favorite tool to generate an [SPDX](https://spdx.dev/) SBOM.

For example purposes, you can use
[`sboms/example.spdx.json`](./sboms/example.spdx.json).

Then attach it to your image (`REF`) using [cosign attest](https://github.com/sigstore/cosign/blob/main/doc/cosign_attest.md)
with the flag `--type spdxjson`, signing "keyless" against the public Fulcio root:
```
export REF="r.example.com/myapp:v0.1.0"
export COSIGN_EXPERIMENTAL=1

cosign attest --yes --type spdxjson \
  --predicate sboms/example.spdx.json \
  "${REF}"
```

Test your image against the policy:

```
export REF="r.example.com/myapp:v0.1.0"

../policy-tester \
  --policy policies/keyless-attestation-sbom-spdxjson.yaml \
  --image "${REF}"
```
