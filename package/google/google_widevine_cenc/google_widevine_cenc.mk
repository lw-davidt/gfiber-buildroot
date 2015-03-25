GOOGLE_WIDEVINE_CENC_SITE = repo://vendor/google/widevine_cenc
WV_DIR := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))

GOOGLE_WIDEVINE_CENC_INSTALL_STAGING = YES

GOOGLE_WIDEVINE_CENC_DEPENDENCIES = protobuf \
				    host-protobuf \
				    host-gyp

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
	popd
endef

define GOOGLE_WIDEVINE_CENC_FIX_PATH
        ln -sf "$(@D)"/wrappers/go/src/gowvcdmstream "$(BUILD_DIR)/go_pkgs/src/"
        ln -sf "$(@D)"/wrappers/go/src/gowvcdm "$(BUILD_DIR)/go_pkgs/src/"
endef

GOOGLE_WIDEVINE_CENC_POST_PATCH_HOOKS += GOOGLE_WIDEVINE_CENC_FIX_PATH

define GOOGLE_WIDEVINE_CENC_INSTALL_STAGING_CMDS
	$(INSTALL) -D "$(@D)/out/Debug/libwvcdm_static.a" "$(STAGING_DIR)/usr/lib/libwvcdm_static.a"
	$(INSTALL) -D "$(@D)/out/Debug/libwvcdm_sysdep.a" "$(STAGING_DIR)/usr/lib/libwvcdm_sysdep.a"
	$(INSTALL) -D "$(@D)/out/Debug/libdevice_files.a" "$(STAGING_DIR)/usr/lib/libdevice_files.a"
	$(INSTALL) -D "$(@D)/out/Debug/liboec_mock.a" "$(STAGING_DIR)/usr/lib/liboec_mock.a"
	$(INSTALL) -D "$(@D)/out/Debug/liblicense_protocol.a" "$(STAGING_DIR)/usr/lib/liblicense_protocol.a"
endef

$(eval $(call GENTARGETS))
