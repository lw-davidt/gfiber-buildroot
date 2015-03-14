GOOGLE_WIDEVINE_CENC_SITE = repo://vendor/google/widevine_cenc
WV_DIR := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))

define GOOGLE_WIDEVINE_CENC_BUILD_CMDS
	export PATH=$(TARGET_PATH):$$PATH ; \
	export PROTOC=$$(dirname $$(which protoc)); \
	export CGO_ENABLED=1; \
	pushd "$(@D)"; \
	mkdir -p platforms/spacecast; \
	cp "$(WV_DIR)"/spacecast_cdm_config.gypi platforms/spacecast; \
	cp -r "$(WV_DIR)"/oemcrypto platforms/spacecast; \
	gyp --depth=. cdm/cdm.gyp -I platforms/spacecast/spacecast_cdm_config.gypi \
	-Dprotoc_dir=$$PROTOC; \
	make -e CC="$(TARGET_CC)" -e CXX="$(TARGET_CXX)"; \
	cd wrappers/go; \
	export $(GOLANG_ENV) ; \
	export GOPATH=$(@D)/wrappers/go:$$GOPATH; \
	cd src/gowvcdmstream; \
	go install; \
	popd
endef

$(eval $(call GENTARGETS))