############
# signing ci
############

.PHONY: sign-policy-images
sign-policy-images:
	cosign sign -a GIT_HASH=$(GIT_HASH) ${KO_PREFIX}/policy-controller:$(GIT_HASH)
	cosign sign -a GIT_HASH=$(GIT_HASH) ${KO_PREFIX}/policy-webhook:$(GIT_HASH)

.PHONY: build-sign-containers
build-sign-containers: ko sign-policy-images
