# Policy Controller

The `policy-controller` admission controller can be used to enforce policy on a Kubernetes cluster based on verifiable supply-chain metadata from `cosign`.

`policy-controller` also resolves the image tags to ensure the image being ran is not different from when it was admitted.

See the [installation instructions](https://docs.sigstore.dev/policy-controller/installation) for more information.

Today, `policy-controller` can automatically validate signatures and
attestations on container images.
Enforcement is configured on a per-namespace basis, and multiple keys are supported.

We're actively working on more features here.

### Enable policy-controller Admission Controller for Namespaces

The `policy-controller` admission controller will only validate resources in namespaces
that have chosen to opt-in. This can be done by adding the label
`policy.sigstore.dev/include: "true"` to the namespace resource.

```bash
kubectl label namespace my-secure-namespace policy.sigstore.dev/include=true
```

### Admission of Images

An image is admitted after it has been validated against all `ClusterImagePolicy` that matched the digest of the image
and that there was at least one valid signature or attestation obtained from the authorities provided in each of the matched `ClusterImagePolicy`.
So each `ClusterImagePolicy` that matches is `AND` for admission, and within each `ClusterImagePolicy` authorities
are `OR`.

See the [Configuring Image Pattern](#configuring-image-patterns) for more information.

An example of an allowed admission would be:
1. If the image matched against `policy1` and `policy3`
1. A valid signature or attestation was obtained for `policy1` with at least one of the `policy1` authorities
1. A valid signature or attestation was obtained for `policy3` with at least one of the `policy3` authorities
1. The image is admitted

An example of a denied admission would be:
1. If the image matched against `policy1` and `policy2`
1. A valid signature or attestation was obtained for `policy1` with at least one of the `policy1` authorities
1. No valid signature or attestation was obtained for `policy2` with at least one of the `policy2` authorities
1. The image is not admitted

In addition to that, the policy controller offers a configurable behavior defining whether to allow, deny or warn whenever an image does not match a policy. This behavior can be configured using the `config-policy-controller` ConfigMap created under the release namespace, and by adding an entry with the property `no-match-policy` and its value `warn|allow|deny`.
By default, any image that does not match a policy is rejected whenever `no-match-policy` is not configured in the ConfigMap.

A table with the `ClusterImagePolicy` available fields can be found [here](./docs/api-types/index.md).

### Configuring policy-controller ClusterImagePolicy

`policy-controller` supports validation against multiple `ClusterImagePolicy` kubernetes resources.

A policy is enforced when an image pattern for the policy is matched against the image being deployed.

#### Configuring Image Patterns

The `ClusterImagePolicy` specifies `spec.images` which specifies a list of `glob` matching patterns.
These matching patterns will be matched against the image digest of PodSpec resources attempting to be deployed.

Glob uses golang [filepath](https://pkg.go.dev/path/filepath#Match) semantics for
matching the images against. Additionally you can specify a more traditional
`**` to match any number of characters. Furthermore to make it easier to specify
 images, there are few defaults when an image is matched, namely:
 * If there is no host in the glob pattern `index.docker.io` is used for the host. This allows users to specify commonly found images from Docker simply as myproject/nginx instead of inded.docker.io/myproject/nginx
 * If the image is specified without multiple path elements (so not separated by `/`), then `library` is defaulted. For example specifying `busybox` will result in library/busybox. And combined with above, will result in match being made against `index.docker.io/library/busybox`.

A sample of a `ClusterImagePolicy` which matches against all images using glob:

```yaml
apiVersion: policy.sigstore.dev/v1beta1
kind: ClusterImagePolicy
metadata:
  name: image-policy
spec:
  images:
  - glob: "**"
```

#### Configuring `key` Authorities

When a policy is selected to be evaluated against the matched image, the authorities will be used to validate signatures and attestations.
If at least one authority is satisfied and a signature is validated, the policy is validated.

Authorities can be `key` specifications, for example:

```yaml
spec:
  authorities:
    - key:
        data: |
          -----BEGIN PUBLIC KEY-----
          ...
          -----END PUBLIC KEY-----
    - key:
        secretRef:
          name: secretName
    - key:
        kms: KMSPATH
```

Each `key` authority can contain these properties:
- `key.data`: specifies the plain text string of the public key
- `key.secretRef.name`: specifies the secret location name in the same namespace where `policy-controller` is installed. <br/> The first key value will be used in the secret.
- `key.kms`: specifies the location for the public key. Supported formats include:
  - `azurekms://[VAULT_NAME][VAULT_URI]/[KEY]`
  - `awskms://[ENDPOINT]/{ARN}` where `ARN` can be either key ARN or alias ARN.
  - `gcpkms://projects/[PROJECT]/locations/global/keyRings/[KEYRING]/cryptoKeys/[KEY]`
  - `hashivault://[KEY]`

#### Configuring `keyless` Authorities

When a policy is selected to be evaluated against the matched image, the authorities will be used to validate signatures.
If at least one authority is satisfied and a signature is validated, the policy is validated.

Authorities can be `keyless` specifications. For example:

```yaml
spec:
  authorities:
    - keyless:
        url: https://fulcio.example.com
        ca-cert:
          data: Certificate Data
    - keyless:
        url: https://fulcio.example.com
        ca-cert:
          secretRef:
            name: secretName
    - keyless:
        identities:
          - issuer: https://accounts.google.com
            subjectRegExp: .*@example.com
          - issuer: https://token.actions.githubusercontent.com
            subject: https://github.com/sigstore/policy-controller/.github/workflows/build.yaml@refs/heads/main

```

Each `keyless` authority can contain these properties:
- `keyless.url`: specifies the Fulcio url
- `keyless.ca-cert`: specifies `ca-cert` information for the `keyless` authority
  - `secretRef.name`: specifies the secret location name in the same namespace where `policy-controller` is installed. <br/>The first key value will be used in the secret for the `ca-cert`.
  - `data`: specifies the inline certificate data
- `keyless.identities`: Identity may contain an array of `issuer` and/or the `subject` found in the transparency log. Either field supports a regex.
  - `issuer`: specifies the issuer found in the transparency log. Exact match is required.
  - `subject`: specifies the subject found in the transparency log. Exact match is required.
  - `issuerRegExp`: specifies the issuer found in the transparency log. Regex patterns are supported. Regex patterns are supported.
  - `subjectRegExp`: specifies the subject found in the transparency log. Regex patterns are supported. Regex patterns are supported.

#### Configuring Remote Signature Location

If signatures are located in a different repository, it can be specified along with the `key` or `keyless` definition.
When no `source` is specified for the key, the expectation is that the signature is colocated with the image.

**Note:** By default, credentials used for the remote source repository are the ones provided in the PodSpec providing resource under `imagePullSecrets`.

To define a `source`, under the corresponding `authorities` node, `source` can be specified.

A sample of source specification for `key` and `keyless`:

```yaml
spec:
  authorities:
    - key:
        data: |
          -----BEGIN PUBLIC KEY-----
          ...
          -----END PUBLIC KEY-----
      source:
        - oci: registry.example.com/project/signature-location
    - keyless:
        url: https://fulcio.example.com
      source:
        - oci: registry.example.com/project/signature-location
```

#### Configure SignaturePullSecrets

If the signatures / attestations are in a different repo or they use different
PullSecrets, you can configure `source` to point to a `secret` which must live
in the same namespace as `policy-controller` webhook (by default `cosign-system`).

```yaml
spec:
  authorities:
    - key:
        data: |
          -----BEGIN PUBLIC KEY-----
          ...
          -----END PUBLIC KEY-----
      source:
        - oci: registry.example.com/project/signature-location
    - keyless:
        url: https://fulcio.example.com
      source:
        - oci: registry.example.com/project/signature-location
          signaturePullSecrets:
          - name: mysecret
```

**Note:** The secret has to be in the format `type: dockerconfigjson`.

#### Configuring Transparency Log

TLog specifies the URL to a transparency log that holds signature and public key information.

When `tlog` key is not specified, the public rekor instance will be used.

```yaml
spec:
  authorities:
    - keyless:
        url: https://fulcio.example.com
      tlog:
        url: https://rekor.example.com
```

#### Configuring Timestamp Authorities

Timestamp authorities specifies the reference to a TrustRoot CR where a timestamp authority has been defined.

```yaml
apiVersion: policy.sigstore.dev/v1alpha1
kind: TrustRoot
metadata:
  name: my-tsa-keys
spec:
  sigstoreKeys:
    certificateAuthorities: []
    timestampAuthorities:
    - subject:
        organization: example.dev
        commonName: example-tsa
      uri: https://tsa.example.dev
      certChain: |-
        CERTIFICATE_CHAIN_IN_BASE64
```

When setting `rfc3161timestamp`, `key` or `keyless` are required.

```yaml
spec:
  authorities:
    - keyless:
        url: https://fulcio.example.com
      identities:
        - issuer: 'https://issuer/'
          subject: 'foo@example.dev'
      rfc3161timestamp:
        trustRootRef: my-tsa-keys
```

#### Configuring policy that validates attestations

Just like with `cosign` CLI you can verify attestations (using `verify-attestation`),
you can configure policies to validate that a particular attestation was signed by
a trusted authority. You do this by using `attestations` array within an `authorities`
section. For example, to configure that a `custom` predicate has to exist and is
attested by the specified `issuer` and `subject`, and the actual `Data` section
of the predicate matches the string `foobar e2e test`:

```yaml
apiVersion: policy.sigstore.dev/v1beta1
kind: ClusterImagePolicy
metadata:
  name: image-policy-keyless-with-attestations
spec:
  images:
  - glob: registry.local:5000/policy-controller/demo*
  authorities:
  - name: verify custom attestation
    keyless:
      url: http://fulcio.fulcio-system.svc
      identities:
      - issuerRegExp: .*kubernetes.default.*
        subjectRegExp: .*kubernetes.io/namespaces/default/serviceaccounts/default
    ctlog:
      url: http://rekor.rekor-system.svc
    attestations:
    - name: custom-match-predicate
      predicateType: custom
      policy:
        type: cue
        data: |
          predicateType: "cosign.sigstore.dev/attestation/v1"
          predicate: Data: "foobar e2e test"
```

`policy` is optional and if left out, only the existence of the attestation is
verified.

#### Configuring policy at the `ClusterImagePolicy` level.

As discussed earlier, by specifying multiple `ClusterImagePolicy` creates an `AND`
clause so that each `ClusterImagePolicy` must be satisfied for an admission, and
having multiple `authorities` creates an `OR` clause so that any matching `authority`
is considered a success, sometimes you may want more flexibility, for example, if you
wanted to specify that at least 2 out of N signatures match, and for those you
can create a single `ClusterImagePolicy` but craft a `policy` that then gets applied
after a `ClusterImagePolicy` has been validated. Here's a bit more complex example
that ties all the bits from above together. It requires there to be two
attestations `custom` and `vuln` and also two signatures, one signed with a `key`
and one `keyless` signature


```yaml
apiVersion: policy.sigstore.dev/v1beta1
kind: ClusterImagePolicy
metadata:
  name: image-policy-requires-two-signatures-two-attestations
spec:
  images:
  - glob: registry.local:5000/policy-controller/demo*
  authorities:
  - name: keylessatt
    keyless:
      url: http://fulcio.fulcio-system.svc
    ctlog:
      url: http://rekor.rekor-system.svc
    attestations:
    - predicateType: custom
      name: customkeyless
      policy:
        type: cue
        data: |
          import "time"
          before: time.Parse(time.RFC3339, "2049-10-09T17:10:27Z")
          predicateType: "cosign.sigstore.dev/attestation/v1"
          predicate: {
            Data: "foobar e2e test"
            Timestamp: <before
          }
    - predicateType: vuln
      name: vulnkeyless
      policy:
        type: cue
        data: |
          import "time"
          before: time.Parse(time.RFC3339, "2022-04-15T17:10:27Z")
          after: time.Parse(time.RFC3339, "2022-03-09T17:10:27Z")
          predicateType: "cosign.sigstore.dev/attestation/vuln/v1"
          predicate: {
            invocation: {
              uri: "invocation.example.com/cosign-testing"
            }
            scanner: {
              uri: "fakescanner.example.com/cosign-testing"
            }
            metadata: {
              scanStartedOn: <before
              scanStartedOn: >after
              scanFinishedOn: <before
              scanFinishedOn: >after
            }
          }
  - name: keyatt
    key:
      data: |
        -----BEGIN PUBLIC KEY-----
        MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEOz9FcbJM/oOkC26Wfo9paG2tYGBL
        usDLHze93DzgLaAPDsyJrygpVnL9M6SOyfyXEsjpBTUu6uFZqHua8hwAlA==
        -----END PUBLIC KEY-----
    ctlog:
      url: http://rekor.rekor-system.svc
    attestations:
    - name: custom-match-predicate
      predicateType: custom
      policy:
        type: cue
        data: |
          predicateType: "cosign.sigstore.dev/attestation/v1"
          predicate: Data: "foobar key e2e test"
  - name: keylesssignature
    keyless:
      url: http://fulcio.fulcio-system.svc
    ctlog:
      url: http://rekor.rekor-system.svc
  - name: keysignature
    key:
      data: |
        -----BEGIN PUBLIC KEY-----
        MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEOz9FcbJM/oOkC26Wfo9paG2tYGBL
        usDLHze93DzgLaAPDsyJrygpVnL9M6SOyfyXEsjpBTUu6uFZqHua8hwAlA==
        -----END PUBLIC KEY-----
    ctlog:
      url: http://rekor.rekor-system.svc
  policy:
    type: cue
    data: |
      package sigstore
      import "struct"
      import "list"
      authorityMatches: {
        keyatt: {
          attestations: struct.MaxFields(1) & struct.MinFields(1)
        },
        keysignature: {
          signatures: list.MaxItems(1) & list.MinItems(1)
        },
        if (len(authorityMatches.keylessatt.attestations) < 2) {
          keylessattMinAttestations: 2
          keylessattMinAttestations: "Error"
        },
        keylesssignature: {
          signatures: list.MaxItems(1) & list.MinItems(1)
        }
      }
```

## Examples

Please see the [examples/](./examples/) directory for example policies etc.

## Policy Testing

This repo includes a `policy-tester` tool which enables checking a policy against
various images.

In the root of this repo, run the following to build:
```
make policy-tester
```

Then run it pointing to a YAML file containing a ClusterImagePolicy, and an image to evaluate the policy against:
```
(set -o pipefail && \
    ./policy-tester \
        --policy=test/testdata/policy-controller/tester/cip-public-keyless.yaml \
        --image=ghcr.io/sigstore/cosign/cosign:v1.9.0 | jq)
```

## Support Policy

This policy-controller's versions are able to run in the following versions of Kubernetes:

|  | policy-controller `> 0.2.x` |
|---|:---:|
| Kubernetes 1.22 | ✓ |
| Kubernetes 1.23 | ✓ |
| Kubernetes 1.24 | ✓ |
| Kubernetes 1.25 | ✓ |

note: not fully tested yet, but can be installed

## Release Cadence

We are intending to move to a monthly cadence for minor releases.
Minor releases will be published around the beginning of the month.
We may cut a patch release instead, if the changes are small enough not to warrant a minor release.
We will also cut patch releases periodically as needed to address bugs.

## Security

Should you discover any security issues, please refer to sigstores [security
process](https://github.com/sigstore/community/blob/main/SECURITY.md)
