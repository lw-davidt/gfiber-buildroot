BCM_APPS_SITE=repo://vendor/broadcom/AppLibs
BCM_APPS_DEPENDENCIES=linux bcm_bseav bcm_nexus
BCM_APPS_CONFIGURE_CMDS=ln -sf $(@D) $(BUILD_DIR)/AppLibs
BCM_APPS_POST_EXTRACT_HOOKS=BCM_REMOVE_PATCH_REJECTS
BCM_APPS_INSTALL_STAGING=YES
BCM_APPS_INSTALL_TARGET=YES

define BCM_REMOVE_PATCH_REJECTS
	find $(@D) -name '*.rej' -exec rm \{\} \;
endef

BCM_APPS_APPLIB_TARGETS=$(BCM_OBJS-y)

BCM_OBJS-$(BR2_PACKAGE_BCM_APP_REFSW)       += refsw
BCM_OBJS-$(BR2_PACKAGE_BCM_APP_DLNA)        += dlna
BCM_OBJS-$(BR2_PACKAGE_BCM_APP_DIRECTFB)    += directfb

ifeq ($(BR2_PACKAGE_BCM_APP_DIRECTFB),y)
BCM_APPS_DEPENDENCIES += bcm_rockford libpng jpeg zlib freetype
endif

ifeq ($(BR2_PACKAGE_DIRECTFB),y)
BCM_APPS_DEPENDENCIES += bcm_rockford libpng jpeg zlib freetype
endif

ifeq ($(BR2_PACKAGE_BCM_APP_BROWSER),y)
BCM_APPS_DEPENDENCIES += openssl expat libcurl libxml2 libxslt fontconfig sqlite pixman cairo
BCM_OBJS-$(BR2_PACKAGE_BCM_APP_BROWSER)     += browser
endif

BCM_OBJS-$(BR2_PACKAGE_BCM_APP_ICU)         += icu


ifeq (y,$(BR2_PACKAGE_BCM_APP_NETFLIX))
BCM_APPS_DEPENDENCIES += openssl expat curl
endif

define BCM_APPS_BUILD_APPS
	$(BCM_MAKE_ENV) $(MAKE1) $(BCM_MAKEFLAGS) -C $(@D)/common $(BCM_APPS_APPLIB_TARGETS)
endef

define BCM_APPS_BUILD_ONE_APP
	rm -f $(BCM_APPS_DIR)/target/97425*.mipsel-linux*$(BCM_APPS_BUILD_TYPE).*tgz
	$(BCM_MAKE_ENV) $(MAKE1) $(BCM_MAKEFLAGS) -C $(BCM_APPS_DIR)/common $(subst bcm_apps_indirect-,,$(1))
	$(BCM_MAKE_ENV) $(MAKE1) $(BCM_MAKEFLAGS) -C $(BCM_APPS_DIR)/common bundle
	$(TAR) -xf $(BCM_APPS_DIR)/target/97425*.mipsel-linux*$(BCM_APPS_BUILD_TYPE).*tgz -C $(STAGING_DIR)
	$(TAR) -xf $(BCM_APPS_DIR)/target/97425*.mipsel-linux*$(BCM_APPS_BUILD_TYPE).*tgz -C $(TARGET_DIR)
endef

ifeq ($(BR2_PACKAGE_BCM_APP_NETFLIX),y)
define BCM_APPS_BUILD_NETFLIX
	$(BCM_MAKE_ENV) NEXUS=$(BCM_NEXUS_DIR) $(MAKE1) $(NETFLIX_MAKEFLAGS) -C $(@D)/thirdparty/netflix/3.x all
endef
endif

ifeq ($(BR2_PACKAGE_BRUNO_DEBUG),y)
BCM_APPS_BUILD_TYPE=debug
else
BCM_APPS_BUILD_TYPE=release
endif

ifeq ($(BR2_PACKAGE_BRUNO_PROD),y)
LICENSE_TYPE=playready_prod_license
else
LICENSE_TYPE=playready_dev_license
endif

define BCM_APPS_BUILD_PLAYREADY_BIN
	mkdir -p $(STAGING_DIR)/usr/local/licenses
	cd /google/src/files/head/depot/google3 && \
	blaze --host_jvm_args=-Xmx256m run --forge -- \
		//isp/fiber/drm:drm_keystore_client \
		--key_type $(LICENSE_TYPE) \
		--output $(STAGING_DIR)/usr/local/licenses/playready.bin
endef

define BCM_APPS_PLAYREADY_INSTALL_TARGET_CMDS
	mkdir -p $(TARGET_DIR)/usr/local/licenses
	cp $(STAGING_DIR)/usr/local/licenses/playready.bin \
		$(TARGET_DIR)/usr/local/licenses/playready.bin
endef

define BCM_APPS_BUILD_CMDS
	$(BCM_APPS_BUILD_PLAYREADY_BIN)
	$(BCM_APPS_BUILD_APPS)
	$(BCM_APPS_BUILD_NETFLIX)
endef

# care must be taken here, as the tarball generated by make bundle is
# unpacked multiple times (once here, once by directfb)
define BCM_APPS_INSTALL_TARGET_CMDS
	rm -f $(@D)/target/97425*.mipsel-linux*$(BCM_APPS_BUILD_TYPE).*tgz
	$(BCM_MAKE_ENV) $(MAKE1) $(BCM_MAKEFLAGS) -C $(@D)/common bundle
	$(TAR) -xf $(@D)/target/97425*.mipsel-linux*$(BCM_APPS_BUILD_TYPE).*tgz -C $(TARGET_DIR)
	$(RM) -f $(TARGET_DIR)/usr/local/lib/modules/nexus.ko
	ln -s ../../../lib/modules/nexus.ko \
	  $(TARGET_DIR)/usr/local/lib/modules/nexus.ko
	$(BCM_APPS_PLAYREADY_INSTALL_TARGET_CMDS)
endef

define BCM_APPS_INSTALL_STAGING_CMDS
	rm -f $(@D)/target/97425*.mipsel-linux*$(BCM_APPS_BUILD_TYPE).*tgz
	$(BCM_MAKE_ENV) $(MAKE1) $(BCM_MAKEFLAGS) -C $(@D)/common bundle
	$(TAR) -xf $(@D)/target/97425*.mipsel-linux*$(BCM_APPS_BUILD_TYPE).*tgz -C $(STAGING_DIR)
endef

$(eval $(call GENTARGETS,package,bcm_apps))

bcm_apps_indirect-%: $(BCM_APPS_TARGET_CONFIGURE)
	@$(call MESSAGE,"$@ building")
	$(call BCM_APPS_BUILD_ONE_APP,$@)
