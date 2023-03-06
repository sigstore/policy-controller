# Policy Controller

The `policy-controller` admission controller can be used to enforce policy on a Kubernetes cluster based on verifiable supply-chain metadata from `cosign`.

`policy-controller` also resolves the image tags to ensure the image being ran is not different from when it was admitted.

See the [installation instructions](https://docs.sigstore.dev/policy-controller/installation) for more information.

Today, `policy-controller` can automatically validate signatures and
attestations on container images.
Enforcement is configured on a per-namespace basis, and multiple keys are supported.

We're actively working on more features here.

For more information about the `policy-controller`, have a look at our documentation website [here](https://docs.sigstore.dev/policy-controller/overview).

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
