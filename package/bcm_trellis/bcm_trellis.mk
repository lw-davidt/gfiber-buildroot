#############################################################
#
# Trellis media player for Chromium
#
#############################################################

BCM_TRELLIS_SITE=repo://vendor/broadcom/trellis
BCM_TRELLIS_DEPENDENCIES=\
	bcm_bseav bcm_nexus bcm_common bcm_rockford \
	google_miniclient \
	libpng jpeg zlib freetype openssl expat \
	libcurl libxml2 libxslt fontconfig boost \
	cairo avahi

# This will result in defining a meaningful APPLIBS_TOP
BCM_APPS_DIR=$(abspath $(@D))

BCM_TRELLIS_INSTALL_STAGING=NO
BCM_TRELLIS_INSTALL_TARGET=YES

define BCM_TRELLIS_CONFIGURE_CMDS
	$(call BCM_COMMON_USE_BUILD_SYSTEM,$(@D))
endef

ifeq ($(BR2_CCACHE),y)
    BCM_TRELLIS_CCACHE="WEBKITGL_CCACHE=y"
else
    BCM_TRELLIS_CCACHE="WEBKITGL_CCACHE=n"
endif

define BCM_TRELLIS_BUILD_CMDS
	$(BCM_MAKE_ENV) $(MAKE) $(BCM_MAKEFLAGS) \
		-C $(@D)/common dlna \
		BUILDING_DLNA=1 BUILDING_PLAYBACK_IP=1 \
		BUILDING_REFSW=1 BUILDING_DTCP_IP=0
	$(BCM_MAKE_ENV) $(MAKE) \
		$(BCM_MAKEFLAGS) \
		-C $(@D)/broadcom/services/media \
		RPM_BUILD_CMD=echo \
		APPLIBS_PROCESS_MODEL=single \
		media_mediaplayer_impl_install \
		TRELLIS_HAS_YOUTUBE_MEDIASOURCE=y
	$(BCM_MAKE_ENV) $(MAKE) \
		$(BCM_MAKEFLAGS) \
		-C $(@D)/broadcom/services/media \
		RPM_BUILD_CMD=echo \
		APPLIBS_PROCESS_MODEL=single \
		media_mediaplayer_impl_static_archive \
		TRELLIS_HAS_YOUTUBE_MEDIASOURCE=y
	$(BCM_MAKE_ENV) $(MAKE) \
		$(BCM_MAKEFLAGS) \
		-C $(@D)/broadcom/services/media \
		RPM_BUILD_CMD=echo \
		APPLIBS_PROCESS_MODEL=single \
		media_filesource_impl_static_archive \
		TRELLIS_HAS_YOUTUBE_MEDIASOURCE=y
	$(BCM_MAKE_ENV) $(MAKE) \
		$(BCM_MAKEFLAGS) \
		-C $(@D)/broadcom/services/media \
		RPM_BUILD_CMD=echo \
		APPLIBS_PROCESS_MODEL=single \
		media_networksource_impl_static_archive \
		TRELLIS_HAS_YOUTUBE_MEDIASOURCE=y
	$(BCM_MAKE_ENV) $(MAKE) \
		$(BCM_MAKEFLAGS) \
		-C $(@D)/broadcom/services/media \
		RPM_BUILD_CMD=echo \
		APPLIBS_PROCESS_MODEL=single \
		media_pushsource_impl_static_archive \
		TRELLIS_HAS_YOUTUBE_MEDIASOURCE=y
endef

define BCM_TRELLIS_INSTALL_TARGET_CMDS
	$(call BCM_COMMON_BUILD_EXTRACT_TARBALL, $(TARGET_DIR))
	if [ -e "$(TARGET_DIR)/usr/local/bin/webkitGl3/chrome-sandbox" ] ; \
		then \
			chmod 4755 "$(TARGET_DIR)/usr/local/bin/webkitGl3/chrome-sandbox"; \
		fi
endef

# Since trellis needs dlna, etc. to be rebuilt and reinstalled to its
# lib directory. We need to remove the stamp to force the reinstall.
define BCM_TRELLIS_DIRCLEAN_CMDS
	$(RM) $(@D)/common/*.stamp
endef

$(eval $(call GENTARGETS))
