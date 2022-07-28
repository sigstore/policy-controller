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

## Validating a policy

Set the `POLICY` and `IMAGE` environment variables appropriately,
pointing to the example policy and image to test:
```
POLICY="policies/some-policy.yaml"
IMAGE="r.example.com/myapp:v0.1.0"
```

Then run the following to validate the image against the policy:
```
../policy-tester --policy "${POLICY}" --image "${IMAGE}"
```

## Example policies

### custom-key-attestation-sbom-spdxjson

Source: [policies/custom-key-attestation-sbom-spdxjson.yaml](./policies/custom-key-attestation-sbom-spdxjson.yaml)

Assert that all images must have a signed SPDX SBOM
(spdxjson) attestation using a custom key.

```
POLICY="policies/custom-key-attestation-sbom-spdxjson.yaml"
```

#### How to satisfy this policy

First, use your favorite tool to generate an [SPDX](https://spdx.dev/) SBOM.

For example purposes, you can use
[`sboms/example.spdx.json`](./sboms/example.spdx.json).

Then attach it to your image using [cosign attest](https://github.com/sigstore/cosign/blob/main/doc/cosign_attest.md)
with the flag `--type spdxjson`, signing it using the private key
located at [`keys/cosign.key`](./keys/cosign.key):
```
export COSIGN_PASSWORD=""

cosign attest --yes --type spdxjson \
  --predicate sboms/example.spdx.json \
  --key keys/cosign.key \
  "${IMAGE}"
```

### keyless-attestation-sbom-spdxjson

Source: [policies/keyless-attestation-sbom-spdxjson.yaml](./policies/keyless-attestation-sbom-spdxjson.yaml)

Assert that all images must have a "keyless"
signed SPDX SBOM (spdxjson) attestation against
the public Fulcio root.

```
POLICY="policies/keyless-attestation-sbom-spdxjson.yaml"
```

#### How to satisfy this policy

First, use your favorite tool to generate an [SPDX](https://spdx.dev/) SBOM.

For example purposes, you can use
[`sboms/example.spdx.json`](./sboms/example.spdx.json).

Then attach it to your image using [cosign attest](https://github.com/sigstore/cosign/blob/main/doc/cosign_attest.md)
with the flag `--type spdxjson`, signing "keyless" against the public Fulcio root:
```
export COSIGN_EXPERIMENTAL=1

cosign attest --yes --type spdxjson \
  --predicate sboms/example.spdx.json \
  "${IMAGE}"
```
