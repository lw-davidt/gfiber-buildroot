GOOGLE_WIDEVINE_CENC_SITE = repo://vendor/google/widevine_cenc
WV_DIR := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))

# This will checkout the widevine go sources from the widevine git repo.
# The git command essentially cherry-picks patches and will be removed when the go cdm sources are commited
# to GOOGLE_WIDEVINE_CENC_SITE.
# TODO(jfore): The cdm configuration should be platform specific. For now this assumes the cdm will be compiled
# for spacecast using the mindspeed soc.
# TODO(jfore): Remove this configure section once the go sources have been reviewed.
define GOOGLE_WIDEVINE_CENC_CONFIGURE_CMDS
	pushd "$(@D)" ; \
	git fetch https://widevine-internal.googlesource.com/cdm refs/changes/10/13010/1 && git checkout FETCH_HEAD; \
	popd
endef

define GOOGLE_WIDEVINE_CENC_BUILD_CMDS
	export PATH=$(TARGET_PATH):$$PATH ; \
	pushd "$(@D)"; \
	gyp --depth=. cdm/cdm.gyp -I "$(WV_DIR)"/spacecast_cdm_config.gypi ; \
	make -e CC="$(TARGET_CC)" -e CXX="$(TARGET_CXX)"; \
	popd
endef

$(eval $(call GENTARGETS))
