#
# Copyright 2021 The Sigstore Authors.
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

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

GOFILES ?= $(shell find . -type f -name '*.go' -not -path "./vendor/*")

# Set version variables for LDFLAGS
PROJECT_ID ?= projectsigstore
RUNTIME_IMAGE ?= gcr.io/distroless/static
GIT_VERSION ?= $(shell git describe --tags --always --dirty)
GIT_HASH ?= $(shell git rev-parse HEAD)
DATE_FMT = +%Y-%m-%dT%H:%M:%SZ
SOURCE_DATE_EPOCH ?= $(shell git log -1 --pretty=%ct)
ifdef SOURCE_DATE_EPOCH
    BUILD_DATE ?= $(shell date -u -d "@$(SOURCE_DATE_EPOCH)" "$(DATE_FMT)" 2>/dev/null || date -u -r "$(SOURCE_DATE_EPOCH)" "$(DATE_FMT)" 2>/dev/null || date -u "$(DATE_FMT)")
else
    BUILD_DATE ?= $(shell date "$(DATE_FMT)")
endif
GIT_TREESTATE = "clean"
DIFF = $(shell git diff --quiet >/dev/null 2>&1; if [ $$? -eq 1 ]; then echo "1"; fi)
ifeq ($(DIFF), 1)
    GIT_TREESTATE = "dirty"
endif

POLICY_CONTROLLER_ARCHS?=all

LDFLAGS=-buildid= -X sigs.k8s.io/release-utils/version.gitVersion=$(GIT_VERSION) \
        -X sigs.k8s.io/release-utils/version.gitCommit=$(GIT_HASH) \
        -X sigs.k8s.io/release-utils/version.gitTreeState=$(GIT_TREESTATE) \
        -X sigs.k8s.io/release-utils/version.buildDate=$(BUILD_DATE)

SRCS = $(shell find cmd -iname "*.go") $(shell find pkg -iname "*.go")

GOLANGCI_LINT_DIR = $(shell pwd)/bin
GOLANGCI_LINT_BIN = $(GOLANGCI_LINT_DIR)/golangci-lint

KO_PREFIX ?= gcr.io/projectsigstore
export KO_DOCKER_REPO=$(KO_PREFIX)
GHCR_PREFIX ?= ghcr.io/sigstore/policy-controller
POLICY_CONTROLLER_YAML ?= policy-controller-$(GIT_VERSION).yaml
LATEST_TAG ?=

.PHONY: all lint test clean policy-controller cross docs
all: policy-controller

log-%:
	@grep -h -E '^$*:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk \
			'BEGIN { \
				FS = ":.*?## " \
			}; \
			{ \
				printf "\033[36m==> %s\033[0m\n", $$2 \
			}'

.PHONY: checkfmt
checkfmt: SHELL := /usr/bin/env bash
checkfmt: ## Check formatting of all go files
	@ $(MAKE) --no-print-directory log-$@
 	$(shell test -z "$(shell gofmt -l $(GOFILES) | tee /dev/stderr)")
 	$(shell test -z "$(shell goimports -l $(GOFILES) | tee /dev/stderr)")

.PHONY: fmt
fmt: ## Format all go files
	@ $(MAKE) --no-print-directory log-$@
	goimports -w $(GOFILES)

## Build policy-controller binary
.PHONY: policy-controller
policy-controller:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $@ ./cmd/webhook

## Build policy-tester binary
.PHONY: policy-tester
policy-tester:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $@ ./cmd/tester

## Build local-dev binary
.PHONY: local-dev
local-dev:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$@ ./cmd/local-dev

#####################
# lint / test section
#####################

golangci-lint:
	rm -f $(GOLANGCI_LINT_BIN) || :
	set -e ;\
	GOBIN=$(GOLANGCI_LINT_DIR) go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.59.1 ;\

lint: golangci-lint ## Run golangci-lint linter
	$(GOLANGCI_LINT_BIN) run -n

test:
	go test $(shell go list ./... | grep -v third_party/)

clean:
	rm -rf policy-controller

KOCACHE_PATH=/tmp/ko
ARTIFACT_HUB_LABELS=--image-label io.artifacthub.package.readme-url="https://raw.githubusercontent.com/sigstore/policy-controller/main/README.md" \
                    --image-label io.artifacthub.package.license=Apache-2.0 --image-label io.artifacthub.package.vendor=sigstore \
                    --image-label io.artifacthub.package.version=0.1.0 \
                    --image-label io.artifacthub.package.name=policy-controller \
                    --image-label org.opencontainers.image.created=$(BUILD_DATE) \
                    --image-label org.opencontainers.image.description="Kubernetes webhook for configuring admission policies" \
                    --image-label io.artifacthub.package.alternative-locations="oci://ghcr.io/sigstore/policy-controller/policy-controller"

define create_kocache_path
  mkdir -p $(KOCACHE_PATH)
endef

##########
# ko build
##########
.PHONY: ko
ko: ko-policy-controller

.PHONY: ko-policy-controller
ko-policy-controller: kustomize-policy-controller
	# policy-controller
	LDFLAGS="$(LDFLAGS)" GIT_HASH=$(GIT_HASH) GIT_VERSION=$(GIT_VERSION) \
	KOCACHE=$(KOCACHE_PATH) KO_DOCKER_REPO=$(KO_PREFIX)/policy-controller ko resolve --bare \
		--platform=$(POLICY_CONTROLLER_ARCHS) --tags $(GIT_VERSION) --tags $(GIT_HASH)$(LATEST_TAG) \
		--image-refs policyControllerImagerefs --filename config/webhook.yaml >> $(POLICY_CONTROLLER_YAML)

.PHONY: ko-local
ko-local:
	LDFLAGS="$(LDFLAGS)" GIT_HASH=$(GIT_HASH) GIT_VERSION=$(GIT_VERSION) \
	KOCACHE=$(KOCACHE_PATH) KO_DOCKER_REPO=ko.local ko build --base-import-paths \
		--tags $(GIT_VERSION) --tags $(GIT_HASH) \
		$(ARTIFACT_HUB_LABELS) \
		--platform=all \
		github.com/sigstore/policy-controller/cmd/webhook

.PHONY: ko-apply
ko-apply:
	LDFLAGS="$(LDFLAGS)" GIT_HASH=$(GIT_HASH) GIT_VERSION=$(GIT_VERSION) ko apply -Bf config/


.PHONY: kustomize-policy-controller
kustomize-policy-controller:
	kustomize build config/ > $(POLICY_CONTROLLER_YAML)

##################
# help
##################

help: # Display help
	@awk -F ':|##' \
		'/^[^\t].+?:.*?##/ {\
			printf "\033[36m%-30s\033[0m %s\n", $$1, $$NF \
		}' $(MAKEFILE_LIST) | sort

include release/release.mk
include test/ci.mk

.PHONY: docs
docs: docs/generate-api

.PHONY: docs/generate-api
docs/generate-api:
	mkdir -p docs/api-types; \
	  go run -ldflags "$(GO_LDFLAGS)" ./cmd/api-docs/main.go \
	    "v1beta1" \
	    `find ./pkg/apis/policy/v1beta1/ -iname '*types.go' |  sort -r | tr '\n' ' '` \
	    > docs/api-types/index.md;
	  go run -ldflags "$(GO_LDFLAGS)" ./cmd/api-docs/main.go \
	    "v1alpha1" \
	    `find ./pkg/apis/policy/v1alpha1/ -iname '*types.go' |  sort -r | tr '\n' ' '` \
	    > docs/api-types/index-v1alpha1.md;

.PHONY: generate-testdata
generate-testdata:
	go run hack/gentestdata/gentestdata.go
