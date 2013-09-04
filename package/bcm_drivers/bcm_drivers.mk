BCM_DRIVERS_SITE=repo://vendor/broadcom/drivers
BCM_DRIVERS_INSTALL_STAGING=YES
BCM_DRIVERS_INSTALL_TARGET=YES
BCM_DRIVERS_DEPENDENCIES=linux google_platform

# TODO(apenwarr): Remove the old moca1 stuff after we fully move to moca2.
ifeq ($(BR2_PACKAGE_BCM_DRIVER_MOCA),y)
define BCM_DRIVERS_BUILD_MOCA
	$(TARGET_MAKE_ENV) $(MAKE1) \
		CROSS=$(TARGET_CROSS) \
		CC="$(TARGET_CC)" \
		EXTRA_CFLAGS="$(TARGET_CFLAGS)" \
		EXTRA_LDFLAGS="$(TARGET_LDFLAGS)" \
		LINUXDIR="$(LINUX_DIR)" \
		ARCH="$(KERNEL_ARCH)" \
		-C $(@D)/moca/
	# Note: we build the moca2 kernel module.  It's compatible.
	$(TARGET_MAKE_ENV) $(MAKE1) \
		CROSS=$(TARGET_CROSS) \
		CC="$(TARGET_CC)" \
		EXTRA_CFLAGS="$(TARGET_CFLAGS)" \
		EXTRA_LDFLAGS="$(TARGET_LDFLAGS)" \
		LINUXDIR="$(LINUX_DIR)" \
		ARCH="$(KERNEL_ARCH)" \
		-C $(@D)/moca2/ bmoca/bmoca.ko
endef

define BCM_DRIVERS_INSTALL_STAGING_MOCA
	$(INSTALL) -m 0644 \
		$(@D)/moca/lib/libmoca.a \
		$(@D)/moca/util/libmocactl.a \
		$(STAGING_DIR)/usr/lib/
	$(INSTALL) -d -m 0755 \
		$(STAGING_DIR)/usr/include/moca
	cp -r $(@D)/moca/include/. $(STAGING_DIR)/usr/include/moca
endef

define BCM_DRIVERS_INSTALL_TARGET_MOCA
	rm -f $(TARGET_DIR)/bin/mocap
	$(INSTALL) -d -m 0755 \
		$(TARGET_DIR)/etc/moca \
		$(TARGET_DIR)/usr/lib/modules
	$(INSTALL) -m 0755 \
		$(@D)/moca/bin/mocad \
		$(@D)/moca/bin/mocactl \
		$(TARGET_DIR)/bin/
	$(INSTALL) -m 0644 \
		$(@D)/moca/mocacore-*.bin \
		$(TARGET_DIR)/etc/moca/
	# Note: we install the moca2 kernel module.  It's compatible.
	$(INSTALL) -m 0644 \
		$(@D)/moca2/bmoca/bmoca.ko \
		$(TARGET_DIR)/usr/lib/modules
endef
endif

ifeq ($(BR2_PACKAGE_BCM_DRIVER_MOCA2),y)
define BCM_DRIVERS_BUILD_MOCA
	$(TARGET_MAKE_ENV) $(MAKE1) \
		CROSS=$(TARGET_CROSS) \
		CC="$(TARGET_CC)" \
		EXTRA_CFLAGS="$(TARGET_CFLAGS)" \
		EXTRA_LDFLAGS="$(TARGET_LDFLAGS)" \
		LINUXDIR="$(LINUX_DIR)" \
		ARCH="$(KERNEL_ARCH)" \
		-C $(@D)/moca2/
endef

define BCM_DRIVERS_INSTALL_STAGING_MOCA
	$(INSTALL) -m 0644 \
		$(@D)/moca2/bin/libmoca.a \
		$(@D)/moca2/bin/libmocacli.a \
		$(STAGING_DIR)/usr/lib/
	$(INSTALL) -d -m 0755 \
		$(STAGING_DIR)/usr/include/moca
	cp -r $(@D)/moca2/include/. $(STAGING_DIR)/usr/include/moca
endef

define BCM_DRIVERS_INSTALL_TARGET_MOCA
	rm -f $(TARGET_DIR)/bin/mocactl
	$(INSTALL) -d -m 0755 \
		$(TARGET_DIR)/etc/moca \
		$(TARGET_DIR)/usr/lib/modules
	$(INSTALL) -m 0755 \
		$(@D)/moca2/bin/mocad \
		$(@D)/moca2/bin/mocap \
		$(TARGET_DIR)/bin/
	$(INSTALL) -m 0644 \
		$(@D)/moca2/moca20core-*.bin \
		$(TARGET_DIR)/etc/moca/
	$(INSTALL) -m 0644 \
		$(@D)/moca2/bmoca/bmoca.ko \
		$(TARGET_DIR)/usr/lib/modules
endef
endif

ifeq ($(BR2_PACKAGE_BCM_DRIVER_WIFI),y)

# NOTE(apenwarr): this could also be set to 'nodebug'.
#  But I don't know what difference that makes.
WIFI_CONFIG_PREFIX=debug

define BCM_DRIVERS_BUILD_WIFI
	$(TARGET_MAKE_ENV) $(MAKE1) \
		STBLINUX=1 \
		LINUXDIR="$(LINUX_DIR)" \
		LD="$(TARGET_LD)" \
		CC="$(TARGET_CC)" \
		AR="$(TARGET_AR)" \
		STRIP="$(TARGET_STRIP)" \
		-C $(@D)/wifi/src/wl/linux \
		mipsel-mips \
		BUILDING_BCM_DRIVERS=1
	$(TARGET_MAKE_ENV) $(MAKE1) \
		TARGETENV="linuxmips" \
		LINUXDIR="$(LINUX_DIR)" \
		LD="$(TARGET_LD)" \
		CC="$(TARGET_CC)" \
		AR="$(TARGET_AR)" \
		STRIP="$(TARGET_STRIP)" \
		-f GNUmakefile \
		-C $(@D)/wifi/src/wl/exe \
		BUILDING_BCM_DRIVERS=1
endef

define BCM_DRIVERS_INSTALL_TARGET_WIFI
	$(INSTALL) -D -m 0600 $(@D)/wifi/src/wl/linux/obj-mipsel-mips-*/wl.ko $(TARGET_DIR)/usr/lib/modules/wl.ko
	$(INSTALL) -m 0700 $(@D)/wifi/src/wl/exe/wlmips $(TARGET_DIR)/usr/bin/wl
endef

endif

define BCM_DRIVERS_BUILD_CMDS
	$(BCM_DRIVERS_BUILD_MOCA)
	$(BCM_DRIVERS_BUILD_WIFI)
endef

define BCM_DRIVERS_CLEAN_CMDS
endef

define BCM_DRIVERS_INSTALL_STAGING_CMDS
	$(BCM_DRIVERS_INSTALL_STAGING_MOCA)
endef

define BCM_DRIVERS_INSTALL_TARGET_CMDS
	$(BCM_DRIVERS_INSTALL_TARGET_MOCA)
	$(BCM_DRIVERS_INSTALL_TARGET_WIFI)
endef

$(eval $(call GENTARGETS))
