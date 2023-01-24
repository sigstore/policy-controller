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

### signed-by-aws-kms-key

Source:  [policies/signed-by-aws-kms.yaml](./policies/signed-by-aws-kms.yaml)

Asserts that images have been signed by a specific AWS KMS key.

```
POLICY="policies/signed-by-aws-kms.yaml"
```

#### How to satisfy this policy

Create (or find) an AWS KMS key to sign your container images and note
the ARN of the key.

```sh
$ aws kms create-key \
  --description "Container signing key" \
  --key-spec ECC_NIST_P256 \
  --key-usage SIGN_VERIFY
{
    "KeyMetadata": {
        "AWSAccountId": "...."
        "Arn": "arn:aws:kms:us-west-2:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab",
        ....
    }
}
```

Next sign your container using the KMS key and `cosign`

```
cosign sign --key "awskms:///<< arn of kms key >>" "${IMAGE}"
```

### signed-by-gcp-kms-key

Source:  [policies/signed-by-gcp-kms.yaml](./policies/signed-by-gcp-kms.yaml)

Asserts that images have been signed by a specific GCP KMS key.

```
POLICY="policies/signed-by-gcp-kms.yaml"
```

#### How to satisfy this policy

Create the GCP KMS keyring and key to sign your container images.

```sh
gcloud kms keyrings create ${KEY_RING} \
    --location ${REGION}
gcloud kms keys create ${KEY_NAME} \
    --keyring ${KEY_RING} \
    --location ${REGION} \
    --purpose asymmetric-signing \
    --default-algorithm ec-sign-p256-sha256
```

Next sign your container using the KMS key and `cosign`.

```sh
gcloud auth application-default login
cosign generate-key-pair \
    --kms gcpkms://projects/${PROJECT_ID}/locations/${REGION}/keyRings/${KEY_RING}/cryptoKeys/${KEY_NAME}
cosign sign \
    --key gcpkms://projects/${PROJECT_ID}/locations/${REGION}/keyRings/${KEY_RING}/cryptoKeys/${KEY_NAME} \
    ${IMAGE}
```

To satisfy the policy, ensure that the policy controller must have `roles/cloudkms.viewer`
and `roles/cloudkms.verifier` IAM permissions on the relevant service account. Also,
the GKE cluster should have the `https://www.googleapis.com/auth/cloudkms` scope.

### signed-by-github-actions

Source:  [policies/signed-by-github-actions.yaml](./policies/signed-by-github-actions.yaml)

Asserts that images have been signed by a specific Github Actions workflow
using keyless signing.

```
POLICY="policies/signed-by-github-actions.yaml"
```

#### How to satisfy this policy

To satisfy this policy you must sign your container image from within a [Github
Actions](https://docs.github.com/en/actions) workflow. Sigstore publishes
a cosign installer action that makes this easy. Here is an example workflow
for signing

```yaml
jobs:
  sign_action:
    runs-on: ubuntu-latest

    permissions:
      contents: read
      id-token: write # NB: needed for signing the images with GitHub OIDC Token

    name: Install Cosign and sign image
    steps:
      - uses: actions/checkout@master
        with:
          fetch-depth: 1

      - name: Install Cosign
        uses: sigstore/cosign-installer@main

      - name: Sign the images with GitHub OIDC Token
        run: cosign sign ${IMAGE}
        env:
          COSIGN_EXPERIMENTAL: true
```

To satisfy the policy, ensure that the path and branch of the workflow match
the workflow URI in the policy.
