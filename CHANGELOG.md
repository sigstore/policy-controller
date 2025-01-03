# v0.12.0

* drop 1.27/28 and add 1.30/31/32 k8s
* fix post submit job
* Use v0.7.18 for scaffolding, update k8s versions to test with

## Contributors

* Carlos Tadeu Panato Junior
* Ville Aikas

# v0.1.0

## Enhancements

* Refactor entire policy validation into ValidatePolicy.
* Set reinvocationPolicy to 'IfNeeded' for the tag resolver webhook
* Add policy-tester CLI for testing ClusterImagePolicies
* (tester) Validate CIP before using it.
* (tester) call SetDefaults on cip before conversion
* remove v1.21 k8s which is deprecated and add v1.24
* chore: do not fail to verify signed images if the secret-name flag is not set

## Bug fixes

* Fix issue #38. Do not block status updates.
* Avoid test race condition.
* Fix https://github.com/sigstore/cosign/issues/1653
* Allow for @ symbol on globs to support image refs with digest
* Validate globs at admission time.
* fix: add missing conversion to CRD
* fix: solve vuln from our opa version
* Fix issue #24
* Bump some vulnerable dependencies; base on distroless/static

## Others

* Bump mikefarah/yq from 4.25.3 to 4.26.1
* Bump actions/dependency-review-action from 2.0.2 to 2.0.4
* Bump google.golang.org/grpc from 1.47.0 to 1.48.0
* Bump github/codeql-action from 2.1.15 to 2.1.16
* Bump actions/cache from 3.0.4 to 3.0.5
* Bump actions/setup-go from 3.2.0 to 3.2.1
* update knative to use v1.5.0 release
* update scafolding to use release v0.3.0
* Bump github.com/aws/aws-sdk-go-v2 from 1.16.6 to 1.16.7
* Bump sigstore/cosign-installer from 2.4.0 to 2.4.1
* Bump github.com/aws/aws-sdk-go-v2 from 1.16.5 to 1.16.6
* increase timeout for golangci-lint
* Bump github.com/stretchr/testify from 1.7.5 to 1.8.0
* Bump github/codeql-action from 2.1.14 to 2.1.15
* Switch to direct returns
* Bump github.com/hashicorp/go-version from 1.5.0 to 1.6.0
* Bump ossf/scorecard-action from 1.1.1 to 1.1.2
* chore: skip secret not found
* Bump github.com/stretchr/testify from 1.7.4 to 1.7.5
* Bump mikefarah/yq from 4.25.2 to 4.25.3
* Bump github/codeql-action from 2.1.13 to 2.1.14
* Bump github.com/google/go-containerregistry from 0.9.0 to 0.10.0
* Bump github.com/stretchr/testify from 1.7.2 to 1.7.4
* Bump github/codeql-action from 2.1.12 to 2.1.13
* Bump actions/dependency-review-action from 2.0.1 to 2.0.2
* Bump actions/dependency-review-action from 1.0.2 to 2.0.1
* Update tests for OR behaviour wrt authorities.
* remove unused struct from imports
* Add policy to make sure signature and attestation is there.
* Return authoritymatches before errors.
* remove third_party stuff due to mismatch in go version.
* Use fulcioroots from sigstore/sigstore
* Even if some authority returns err, return any other matching authority results.
* Use public fulcio/rekor to make sure things are not there.
* hack/update-deps.sh

## Contributors

* Carlos Tadeu Panato Junior
* Hector Fernandez
* Jason Hall
* Josh Dolitsky
* Matt Moore
* Ville Aikas
* Vladimir Nachev
* cpanato
* dependabot[bot]
* dlorenc
* hectorj2f
