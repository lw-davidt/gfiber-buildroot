#############################################################
#
# Broadcom's directfb (linked to nexus, rockford, magnum)
#
#############################################################
BCM_DIRECTFB_SITE = repo://vendor/broadcom/directfb
BCM_DIRECTFB_INSTALL_STAGING = YES
BCM_DIRECTFB_INSTALL_TARGET = YES
BCM_DIRECTFB_DEPENDENCIES = \
	bcm_common bcm_nexus bcm_rockford \
	bcm_magnum bcm_bseav freetype jpeg libpng zlib google_miniclient

define BCM_DIRECTFB_REMOVE_CONFIG
	rm -f $(TARGET_DIR)/usr/local/bin/directfb/$(DIRECTFB_VERSION_MAJOR)/directfb-config
endef

BCM_DIRECTFB_POST_INSTALL_TARGET_HOOKS += BCM_DIRECTFB_REMOVE_CONFIG

define BCM_DIRECTFB_BUILD_CMDS
	$(call BCM_COMMON_USE_BUILD_SYSTEM,$(@D))
	$(BCM_MAKE_ENV) NEXUS_MODE=client $(MAKE1) \
		$(BCM_MAKEFLAGS) APPLIBS_TOP=$(@D) \
		NEXUS_BIN_DIR=$(BCM_NEXUS_DIR)/bin \
		-C $(@D)/common directfb \
		DIRECTFB_NSC_SUPPORT=y \
		BUILDING_DIRECTFB=1
endef

define BCM_DIRECTFB_INSTALL_STAGING_CMDS
	$(call BCM_COMMON_BUILD_EXTRACT_TARBALL,$(STAGING_DIR))
endef

define BCM_DIRECTFB_INSTALL_TARGET_CMDS
	$(call BCM_COMMON_BUILD_EXTRACT_TARBALL,$(TARGET_DIR))
endef


$(eval $(call GENTARGETS))
