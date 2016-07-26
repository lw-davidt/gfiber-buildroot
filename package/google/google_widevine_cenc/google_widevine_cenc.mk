GOOGLE_WIDEVINE_CENC_SITE = repo://vendor/google/widevine_cenc
WV_DIR := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))

GOOGLE_WIDEVINE_CENC_INSTALL_STAGING = YES

GOOGLE_WIDEVINE_CENC_DEPENDENCIES = protobuf \
				    host-protobuf \
				    host-gyp \
				    openssl
ifeq ($(BR2_PACKAGE_BCM_NEXUS),y)
GOOGLE_WIDEVINE_CENC_DEPENDENCIES += bcm_nexus
endif

GOOGLE_WIDEVINE_CENC_BUILD_ENV =
GOOGLE_WIDEVINE_CENC_BUILD_ENV += V=1
GOOGLE_WIDEVINE_CENC_BUILD_ENV += BUILDTYPE=Release
ifeq ($(BR2_PACKAGE_GOOGLE_SPACECAST),y)
GOOGLE_WIDEVINE_CENC_BUILD_ENV += CGO_ENABLED=1
endif

ifeq ($(BR2_PACKAGE_GOOGLE_SPACECAST),y)

define GOOGLE_WIDEVINE_CENC_BUILD_CMDS
	pushd "$(@D)"; \
	mkdir -p platforms/spacecast; \
	cp "$(WV_DIR)"/spacecast_cdm_config.gypi platforms/spacecast; \
	cp -r "$(WV_DIR)"/oemcrypto platforms/spacecast; \
	cp "$(WV_DIR)"/spacecast_cdm.gyp platforms/spacecast; \
	cp -r "$(WV_DIR)"/include platforms/spacecast; \
	cp -r "$(WV_DIR)"/src platforms/spacecast; \
	rm -f wrappers/go/src/gowvcdm/gowvcdm_x86-64.go.go; \
	cp "$(WV_DIR)"/gowvcdm_cgo.go wrappers/go/src/gowvcdm; \
	mkdir -p "$(@D)"/wrappers/go/src/video_widevine_server_sdk; \
	PATH="$(TARGET_PATH)" $(GOOGLE_WIDEVINE_CENC_BUILD_ENV) gyp \
		--depth=. platforms/spacecast/spacecast_cdm.gyp \
		-Iplatforms/spacecast/spacecast_cdm_config.gypi \
		-Dprotoc_dir=$$$(dirname $$(which protoc)); \
	PATH="$(TARGET_PATH)" $(GOOGLE_WIDEVINE_CENC_BUILD_ENV) make \
		-e CC="$(TARGET_CC)" \
		-e CXX="$(TARGET_CXX)" -e CXXFLAGS="$(TARGET_CXXFLAGS)"; \
	popd
endef

define HOST_GOOGLE_WIDEVINE_CENC_BUILD_CMDS
	pushd "$(@D)"; \
	mkdir -p platforms/spacecast; \
	cp "$(WV_DIR)"/spacecast_cdm_config.gypi platforms/spacecast; \
	cp -r "$(WV_DIR)"/oemcrypto platforms/spacecast; \
	cp "$(WV_DIR)"/spacecast_cdm.gyp platforms/spacecast; \
	cp -r "$(WV_DIR)"/include platforms/spacecast; \
	cp -r "$(WV_DIR)"/src platforms/spacecast; \
	rm -f wrappers/go/src/gowvcdm/gowvcdm_x86-64.go.go; \
	cp "$(WV_DIR)"/gowvcdm_cgo.go wrappers/go/src/gowvcdm; \
	mkdir -p "$(@D)"/wrappers/go/src/video_widevine_server_sdk; \
	PATH="$(HOST_PATH)" $(GOOGLE_WIDEVINE_CENC_BUILD_ENV) gyp \
		--depth=. platforms/spacecast/spacecast_cdm.gyp \
		-Iplatforms/spacecast/spacecast_cdm_config.gypi \
		-Dprotoc_dir=$$$(dirname $$(which protoc)); \
	PATH="$(HOST_PATH)" $(GOOGLE_WIDEVINE_CENC_BUILD_ENV) make \
		-e CC="$(HOSTCC)" \
		-e CXX="$(HOSTCXX)" -e CXXFLAGS="$(HOST_CXXFLAGS)"; \
	popd
endef

else

define GOOGLE_WIDEVINE_CENC_NEXUS_PATCHES
	support/scripts/apply-patches.sh $(@D) package/google/google_widevine_cenc cdm_test_nexus.patch;
endef

GOOGLE_WIDEVINE_CENC_POST_PATCH_HOOKS = GOOGLE_WIDEVINE_CENC_NEXUS_PATCHES

define GOOGLE_WIDEVINE_CENC_BUILD_CMDS
	pushd "$(@D)"; \
	mkdir -p platforms/fibertv; \
	cp "$(WV_DIR)"/fibertv_cdm_config.gypi platforms/fibertv; \
	cp "$(WV_DIR)"/fibertv_cdm.gyp platforms/fibertv; \
	cp -r "$(WV_DIR)"/include platforms/fibertv; \
	cp -r "$(WV_DIR)"/src platforms/fibertv; \
	PATH="$(TARGET_PATH)" $(GOOGLE_WIDEVINE_CENC_BUILD_ENV) gyp \
		--depth=. platforms/fibertv/fibertv_cdm.gyp \
		-Iplatforms/fibertv/fibertv_cdm_config.gypi \
		-Dprotoc_dir=$$$(dirname $$(which protoc)); \
	PATH="$(TARGET_PATH)" $(GOOGLE_WIDEVINE_CENC_BUILD_ENV) make \
		-e CC="$(TARGET_CC)" \
		-e CXX="$(TARGET_CXX)" -e CXXFLAGS="$(TARGET_CXXFLAGS)"; \
	popd
endef

endif

define GOOGLE_WIDEVINE_CENC_FIX_PATH
        mkdir -p "$(BUILD_DIR)/go_pkgs/src"
        ln -sfT "$(@D)"/wrappers/go/src/gowvcdmstream "$(BUILD_DIR)/go_pkgs/src/gowvcdmstream"
        ln -sfT "$(@D)"/wrappers/go/src/gowvcdm "$(BUILD_DIR)/go_pkgs/src/gowvcdm"
        ln -sfT "$(@D)"/wrappers/go/src/video_drm "$(BUILD_DIR)/go_pkgs/src/video_drm"
        ln -sfT "$(@D)"/wrappers/go/src/video_widevine_server_sdk "$(BUILD_DIR)/go_pkgs/src/video_widevine_server_sdk"
endef

ifeq ($(BR2_PACKAGE_GOOGLE_SPACECAST),y)
GOOGLE_WIDEVINE_CENC_POST_PATCH_HOOKS += GOOGLE_WIDEVINE_CENC_FIX_PATH
endif

ifeq ($(BR2_PACKAGE_GOOGLE_SPACECAST),y)

define GOOGLE_WIDEVINE_CENC_INSTALL_STAGING_CMDS
	$(INSTALL) -D "$(@D)/out/Release/libwidevine_cdm_core.a" "$(STAGING_DIR)/usr/lib/libwidevine_cdm_core.a"
	$(INSTALL) -D "$(@D)/out/Release/libwidevine_ce_cdm_static.a" "$(STAGING_DIR)/usr/lib/libwidevine_ce_cdm_static.a"
	$(INSTALL) -D "$(@D)/out/Release/libdevice_files.a" "$(STAGING_DIR)/usr/lib/libdevice_files.a"
	$(INSTALL) -D "$(@D)/out/Release/liboec_mock.a" "$(STAGING_DIR)/usr/lib/liboec_mock.a"
	$(INSTALL) -D "$(@D)/out/Release/liblicense_protocol.a" "$(STAGING_DIR)/usr/lib/liblicense_protocol.a"
endef

define HOST_GOOGLE_WIDEVINE_CENC_INSTALL_CMDS
	$(INSTALL) -D "$(@D)/out/Release/libwidevine_cdm_core.a" "$(HOST_DIR)/usr/lib/libwidevine_cdm_core.a"
	$(INSTALL) -D "$(@D)/out/Release/libwidevine_ce_cdm_static.a" "$(HOST_DIR)/usr/lib/libwidevine_ce_cdm_static.a"
	$(INSTALL) -D "$(@D)/out/Release/libdevice_files.a" "$(HOST_DIR)/usr/lib/libdevice_files.a"
	$(INSTALL) -D "$(@D)/out/Release/liboec_mock.a" "$(HOST_DIR)/usr/lib/liboec_mock.a"
	$(INSTALL) -D "$(@D)/out/Release/liblicense_protocol.a" "$(HOST_DIR)/usr/lib/liblicense_protocol.a"
endef

else

define GOOGLE_WIDEVINE_CENC_INSTALL_STAGING_CMDS
	$(INSTALL) -D "$(@D)/out/Release/lib.target/libwidevine_ce_cdm_shared.so" "$(STAGING_DIR)/usr/lib/libwidevine_ce_cdm_shared.so"

endef

define GOOGLE_WIDEVINE_CENC_INSTALL_TARGET_CMDS
	$(INSTALL) -D "$(@D)/out/Release/lib.target/libwidevine_ce_cdm_shared.so" "$(TARGET_DIR)/usr/lib/libwidevine_ce_cdm_shared.so"
endef
endif

$(eval $(call GENTARGETS))
$(eval $(call GENTARGETS,host))
