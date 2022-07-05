# Policy Controller

Kubernetes webhook for configuring admission policies.

(TODO: vaikas) Update this README

## ClusterImagePolicy Testing

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

## Security

Should you discover any security issues, please refer to sigstores [security
process](https://github.com/sigstore/community/blob/main/SECURITY.md)
