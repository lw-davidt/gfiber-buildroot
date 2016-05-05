GOOGLE_WIDEVINE_CENC_SITE = repo://vendor/google/widevine_cenc
WV_DIR := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))

GOOGLE_WIDEVINE_CENC_INSTALL_STAGING = YES

GOOGLE_WIDEVINE_CENC_DEPENDENCIES = protobuf \
				    host-protobuf \
				    host-gyp \
				    openssl

define GOOGLE_WIDEVINE_CENC_BUILD_CMDS
	export PATH=$(TARGET_PATH):$$PATH; \
	export PROTOC=$$(dirname $$(which protoc)); \
	export CGO_ENABLED=1; \
	export V=1; \
	export BUILDTYPE=Release; \
	pushd "$(@D)"; \
	mkdir -p platforms/spacecast; \
	cp "$(WV_DIR)"/spacecast_cdm_config.gypi platforms/spacecast; \
	cp -r "$(WV_DIR)"/oemcrypto platforms/spacecast; \
	cp "$(WV_DIR)"/spacecast_cdm.gyp platforms/spacecast; \
	cp -r "$(WV_DIR)"/include platforms/spacecast; \
	cp -r "$(WV_DIR)"/src platforms/spacecast; \
	cp -r "$(WV_DIR)"/gowvcdm_linux_arm.go wrappers/go/src/gowvcdm; \
	mkdir -p "$(@D)"/wrappers/go/src/video_widevine_server_sdk; \
	gyp --depth=. platforms/spacecast/spacecast_cdm.gyp -Iplatforms/spacecast/spacecast_cdm_config.gypi \
	-Dprotoc_dir=$$PROTOC; \
	make -e CC="$(TARGET_CC)" -e CXX="$(TARGET_CXX)"; \
	popd
endef

define GOOGLE_WIDEVINE_CENC_FIX_PATH
        mkdir -p "$(BUILD_DIR)/go_pkgs/src"
        ln -sfT "$(@D)"/wrappers/go/src/gowvcdmstream "$(BUILD_DIR)/go_pkgs/src/gowvcdmstream"
        ln -sfT "$(@D)"/wrappers/go/src/gowvcdm "$(BUILD_DIR)/go_pkgs/src/gowvcdm"
        ln -sfT "$(@D)"/wrappers/go/src/video_drm "$(BUILD_DIR)/go_pkgs/src/video_drm"
        ln -sfT "$(@D)"/wrappers/go/src/video_widevine_server_sdk "$(BUILD_DIR)/go_pkgs/src/video_widevine_server_sdk"
endef

GOOGLE_WIDEVINE_CENC_POST_PATCH_HOOKS += GOOGLE_WIDEVINE_CENC_FIX_PATH

define GOOGLE_WIDEVINE_CENC_INSTALL_STAGING_CMDS
	$(INSTALL) -D "$(@D)/out/Release/libwidevine_cdm_core.a" "$(STAGING_DIR)/usr/lib/libwidevine_cdm_core.a"
	$(INSTALL) -D "$(@D)/out/Release/libwidevine_ce_cdm_static.a" "$(STAGING_DIR)/usr/lib/libwidevine_ce_cdm_static.a"
	$(INSTALL) -D "$(@D)/out/Release/libdevice_files.a" "$(STAGING_DIR)/usr/lib/libdevice_files.a"
	$(INSTALL) -D "$(@D)/out/Release/liboec_mock.a" "$(STAGING_DIR)/usr/lib/liboec_mock.a"
	$(INSTALL) -D "$(@D)/out/Release/liblicense_protocol.a" "$(STAGING_DIR)/usr/lib/liblicense_protocol.a"
endef

$(eval $(call GENTARGETS))
