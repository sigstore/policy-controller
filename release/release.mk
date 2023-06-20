######################
# sign section
######################

.PHONY: build-sign-release-images
build-sign-release-images: ko
	GIT_HASH=$(GIT_HASH) GIT_VERSION=$(GIT_VERSION) \
	./release/ko-sign-release-images.sh

####################
# copy image to GHCR
####################

.PHONY: copy-policy-controller-signed-release-to-ghcr
copy-policy-controller-signed-release-to-ghcr:
	cosign copy $(KO_PREFIX)/policy-controller:$(GIT_VERSION) $(GHCR_PREFIX)/policy-controller:$(GIT_VERSION)

.PHONY: copy-signed-release-to-ghcr
copy-signed-release-to-ghcr: copy-policy-controller-signed-release-to-ghcr
