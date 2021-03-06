# Google platform image creation for Bruno platform
#
#
# WARNING WARNING WARNING
#
# Because of how buildroot handles fs generation macros, it EATS DOUBLE
# QUOTES.  Use only single quotes in all shell commands in this file, or
# you'll get very weird, hard-to-find errors.

ROOTFS_GINSTALL_DEPENDENCIES = host-mtd

ifeq ($(BR2_TARGET_ROOTFS_RECOVERYFS),y)
ROOTFS_GINSTALL_DEPENDENCIES += rootfs-recoveryfs
endif

INITRAMFS_IMAGE=initramfs.cpio.gz
INITRAMFS_COMPRESS_COMMAND='gzip -c'

ifeq ($(BR2_PACKAGE_SIMPLERAMFS),y)
ROOTFS_GINSTALL_DEPENDENCIES += simpleramfs
ifeq ($(BR2_PACKAGE_SIMPLERAMFS_XZ),y)
INITRAMFS_IMAGE=initramfs.cpio.xz
INITRAMFS_COMPRESS_COMMAND='xz -c --check=crc32 --lzma2=dict=1MiB'
endif
endif

ifeq ($(BR2_TARGET_ROOTFS_INITRAMFS),y)
ROOTFS_GINSTALL_DEPENDENCIES += rootfs-initramfs
endif

ifeq ($(BR2_TARGET_ROOTFS_SQUASHFS),y)
ROOTFS_GINSTALL_DEPENDENCIES += rootfs-squashfs host-dmverity host-google_signing
endif

ROOTFS_GINSTALL_VERSION = $(shell cat $(BINARIES_DIR)/version)
ROOTFS_GINSTALL_PLATFORMS = $(shell echo $(BR2_TARGET_GENERIC_PLATFORMS_SUPPORTED) | sed 's/[, ][, ]*/, /g' | tr a-z A-Z)

PLAT_NAME=$(call qstrip,$(BR2_TARGET_GENERIC_PLATFORM_NAME))

#
# Broadcom/CFE - GFHD100 (thin bruno), GFMS100 (fat bruno), GFHD200 (camaro)
#
ifneq ($(findstring $(PLAT_NAME),gfibertv gftv200),)
# Config strings have quotes around them for some reason, which causes
# trouble.  This trick removes them.
BRUNO_CFE_DIR = $(call qstrip,$(BR2_TARGET_ROOTFS_GINSTALL_LOADER_DIR))
ifeq ($(BR2_PACKAGE_GOOGLE_PROD),y)
# Always install the prod bootloader when building prod images
_BRUNO_LOADER = cfe_signed_release
# Don't set the type to prod if building an unsigned image
ifeq ($(BR2_PACKAGE_GOOGLE_UNSIGNED),y)
ROOTFS_GINSTALL_TYPE=prod_unsigned
else
ROOTFS_GINSTALL_TYPE=prod
endif
else ifeq ($(BR2_PACKAGE_GOOGLE_OPENBOX),y)
_BRUNO_LOADER = cfe_signed_openbox
ROOTFS_GINSTALL_TYPE=openbox
else
_BRUNO_LOADER = cfe_signed_unlocked
ROOTFS_GINSTALL_TYPE=unlocked
endif

# These will be blank if the given files don't exist (eg. if you don't have
# access to the right repositories) and then we'll just leave them out of
# the build.  The resulting image will not contain a bootloader, which is
# ok; we'll just leave the existing bootloader in place.
BRUNO_LOADER     := $(wildcard $(BRUNO_CFE_DIR)/$(_BRUNO_LOADER).bin)
BRUNO_LOADER_SIG := $(wildcard $(BRUNO_CFE_DIR)/$(_BRUNO_LOADER).sig)
ifneq ($(BRUNO_LOADER),)
# We intentionally changed the filenames from v2 to v3 to prevent really
# harmful installs due to accidental half-compatibility.
BRUNO_LOADERS_V2 := loader.bin loader.sig
BRUNO_LOADERS_V3_V4 := loader.img loader.sig
endif

ROOTFS_GINSTALL_KERNEL_FILE=vmlinuz
BRUNO_SIGNING=y
endif  # gfibertv gftv200

#
# Broadcom/Bolt - GFHD254 (Lockdown)
#
ifneq ($(findstring $(PLAT_NAME),gftv254),)
BOLT_DIR = $(call qstrip,$(BR2_TARGET_ROOTFS_GINSTALL_LOADER_DIR))
ifeq ($(BR2_PACKAGE_GOOGLE_PROD),y)
_BRUNO_LOADER = bolt_signed_release
ifeq ($(BR2_PACKAGE_GOOGLE_UNSIGNED),y)
ROOTFS_GINSTALL_TYPE=prod_unsigned
else
ROOTFS_GINSTALL_TYPE=prod
endif
else ifeq ($(BR2_PACKAGE_GOOGLE_OPENBOX),y)
_BRUNO_LOADER = bolt_signed_openbox
ROOTFS_GINSTALL_TYPE=openbox
else
_BRUNO_LOADER = bolt_signed_unlocked
ROOTFS_GINSTALL_TYPE=unlocked
endif

# These will be blank if the given files don't exist (eg. if you don't have
# access to the right repositories) and then we'll just leave them out of
# the build.  The resulting image will not contain a bootloader, which is
# ok; we'll just leave the existing bootloader in place.
BRUNO_LOADER     := $(wildcard $(BOLT_DIR)/$(_BRUNO_LOADER).bin)
BRUNO_LOADER_SIG := $(wildcard $(BOLT_DIR)/$(_BRUNO_LOADER).sig)
ifneq ($(BRUNO_LOADER),)
# We intentionally changed the filenames from v2 to v3 to prevent really
# harmful installs due to accidental half-compatibility.
BRUNO_LOADERS_V3_V4 := loader.img loader.sig
endif
ROOTFS_GINSTALL_KERNEL_FILE=zImage_signed
BRUNOv2_SIGNING=y
endif  # gftv254

#
# Mindspeed/Barebox - GFRG200/210/250, GFSC100, GJCB100
#
ifneq ($(findstring $(PLAT_NAME),gfrg200 gfsc100 gjcb100),)
ifeq ($(BR2_PACKAGE_GOOGLE_KEY_SUFFIX),"")
# Config strings have quotes around them for some reason, which causes
# trouble.  This trick removes them.
LOADER_DIR = $(call qstrip,$(BR2_TARGET_ROOTFS_GINSTALL_LOADER_DIR))
else
LOADER_DIR = $(call qstrip,$(BR2_TARGET_ROOTFS_GINSTALL_LOADER_DIR)/$(BR2_PACKAGE_GOOGLE_KEY_SUFFIX))
endif

ifeq ($(BR2_PACKAGE_GOOGLE_PROD),y)
_BAREBOX = barebox_signed_release
ifeq ($(BR2_PACKAGE_GOOGLE_UNSIGNED),y)
ROOTFS_GINSTALL_TYPE=prod_unsigned
else
ROOTFS_GINSTALL_TYPE=prod
endif
else
_BAREBOX = barebox_signed_unlocked
ROOTFS_GINSTALL_TYPE=unlocked
endif
_ULOADER = uloader_signed_release

# These will be blank if the given files don't exist (eg. if you don't have
# access to the right repositories) and then we'll just leave them out of
# the build.  The resulting image will not contain a bootloader, which is
# ok; we'll just leave the existing bootloader in place.
BAREBOX     := $(wildcard $(LOADER_DIR)/$(_BAREBOX).bin)
BAREBOX_SIG := $(wildcard $(LOADER_DIR)/$(_BAREBOX).sig)

# Don't include a uloader, until ginstall is smart enough to not downgrade the
# uloader if a newer one is in the flash.
ifeq (true,false)
ULOADER     := $(wildcard $(LOADER_DIR)/$(_ULOADER).bin)
ULOADER_SIG := $(wildcard $(LOADER_DIR)/$(_ULOADER).sig)
endif

ifneq ($(BAREBOX),)
BRUNO_LOADERS_V3_V4 := $(BRUNO_LOADERS_V3_V4) loader.img loader.sig
endif
ifneq ($(ULOADER),)
BRUNO_LOADERS_V3_V4 := $(BRUNO_LOADERS_V3_V4) uloader.img uloader.sig
endif
ROOTFS_GINSTALL_KERNEL_FILE=uImage
OPTIMUS_SIGNING=y
BUILD_UIMAGE=y
MKIMAGE_KERNEL_LOAD_ADDRESS = 0x04008000
MKIMAGE_KERNEL_ENTRY_POINT = 0x04008000
MKIMAGE_DATA_FILE=zImage:$(INITRAMFS_IMAGE)
MKIMAGE_IMAGE_TYPE=multi
MKIMAGE_COMPRESSION_TYPE=none
MKIMAGE_EXTRA_FLAGS=
endif # gfrg200 gfsc100 gjcb100

#
# Arc/uboot - Frenzy, Skids, Prowl
#
ifneq ($(findstring $(PLAT_NAME),gfex250 gffrenzy gfrg240),)

# Include a u-boot image if it exists.
ifeq ($(PLAT_NAME),gfrg240)
LOADER_DIR = $(call qstrip,$(BR2_TARGET_ROOTFS_GINSTALL_LOADER_DIR))
ifeq ($(BR2_PACKAGE_GOOGLE_PROD),y)
_BRUNO_LOADER = u-boot-prod
ROOTFS_GINSTALL_TYPE=prod
else ifeq ($(BR2_PACKAGE_GOOGLE_OPENBOX),y)
_BRUNO_LOADER = u-boot-openbox
ROOTFS_GINSTALL_TYPE=openbox
else
_BRUNO_LOADER = u-boot-dev
ROOTFS_GINSTALL_TYPE=unlocked
endif

BRUNO_LOADER     := $(wildcard $(LOADER_DIR)/$(_BRUNO_LOADER).bin)
BRUNO_LOADER_SIG := $(wildcard $(LOADER_DIR)/$(_BRUNO_LOADER).sig)
ifneq ($(BRUNO_LOADER),)
BRUNO_LOADERS_V3_V4 := loader.img loader.sig
endif
endif # gfrg240

# lzma compressed uImage is already available from the kernel build
ROOTFS_GINSTALL_KERNEL_FILE=uImage
endif # gfex250 gffrenzy gfrg240

#
# Armada/uboot - GFCH100 (chimera)
#
ifneq ($(findstring $(PLAT_NAME),gfch100),)
LOADER_DIR = $(call qstrip,$(BR2_TARGET_ROOTFS_GINSTALL_LOADER_DIR))
ifeq ($(BR2_PACKAGE_GOOGLE_PROD),y)
_BRUNO_LOADER = u-boot-spi-prod
ifeq ($(BR2_PACKAGE_GOOGLE_UNSIGNED),y)
ROOTFS_GINSTALL_TYPE=prod_unsigned
else
ROOTFS_GINSTALL_TYPE=prod
endif
else ifeq ($(BR2_PACKAGE_GOOGLE_OPENBOX),y)
_BRUNO_LOADER = u-boot-spi-openbox
ROOTFS_GINSTALL_TYPE=openbox
else
_BRUNO_LOADER = u-boot-spi-dev
ROOTFS_GINSTALL_TYPE=unlocked
endif

BRUNO_LOADER     := $(wildcard $(LOADER_DIR)/$(_BRUNO_LOADER).bin)
BRUNO_LOADER_SIG := $(wildcard $(LOADER_DIR)/$(_BRUNO_LOADER).sig)
ifneq ($(BRUNO_LOADER),)
BRUNO_LOADERS_V3_V4 := loader.img loader.sig
endif

ROOTFS_GINSTALL_KERNEL_FILE = uImage
OPTIMUS_SIGNING=y
BUILD_UIMAGE=y
MKIMAGE_KERNEL_LOAD_ADDRESS = 0x04008000
MKIMAGE_KERNEL_ENTRY_POINT = 0x04008000
MKIMAGE_DATA_FILE=zImage:$(INITRAMFS_IMAGE):gfch100.dtb
MKIMAGE_IMAGE_TYPE=multi
MKIMAGE_COMPRESSION_TYPE=none
MKIMAGE_EXTRA_FLAGS=
endif # gfch100

#
# sanity check
#
ifeq ($(BR2_TARGET_ROOTFS_GINSTALL_V3)$(BR2_TARGET_ROOTFS_GINSTALL_V4),y)
ifndef ROOTFS_GINSTALL_KERNEL_FILE
$(error ROOTFS_GINSTALL_KERNEL_FILE is not defined for platform '$(PLAT_NAME)')
endif
endif

ifeq ($(BR2_TARGET_ROOTFS_SQUASHFS),y)
ROOTFS_GINSTALL_FILESYSTEM_FILE := rootfs.img
endif

# v3 and v4 image formats contain a manifest file, which describes the image
# and supported platforms.
#
# Note: need to use $(value XYZ) for XYZ variables that change during
# the build process (eg. because they read a file), since variable
# substitutions in this macro happen at macro define time, not
# runtime, unlike other make variables.
ifeq ($(BR2_TARGET_ROOTFS_GINSTALL_V4),y)
ROOTFS_GINSTALL_MANIFEST=MANIFEST
ROOTFS_GINSTALL_INSTALLER_VERSION=4
else
ROOTFS_GINSTALL_MANIFEST=manifest
ROOTFS_GINSTALL_INSTALLER_VERSION=3
endif
define ROOTFS_GINSTALL_CMD_V3_V4
	set -e; \
	rm -f $(BINARIES_DIR)/$(ROOTFS_GINSTALL_MANIFEST) && \
	echo 'installer_version: $(ROOTFS_GINSTALL_INSTALLER_VERSION)' >>$(BINARIES_DIR)/$(ROOTFS_GINSTALL_MANIFEST) && \
	if [ '$(BR2_TARGET_ROOTFS_GINSTALL_V4)' = 'y' ]; then \
		echo 'minimum_version: $(BR2_TARGET_ROOTFS_GINSTALL_MINIMUM_VERSION)' >>$(BINARIES_DIR)/$(ROOTFS_GINSTALL_MANIFEST); \
	fi && \
	echo 'image_type: $(ROOTFS_GINSTALL_TYPE)' >>$(BINARIES_DIR)/$(ROOTFS_GINSTALL_MANIFEST) && \
	echo 'version: $(value ROOTFS_GINSTALL_VERSION)' >>$(BINARIES_DIR)/$(ROOTFS_GINSTALL_MANIFEST) && \
	echo 'platforms: [ $(ROOTFS_GINSTALL_PLATFORMS) ]' >>$(BINARIES_DIR)/$(ROOTFS_GINSTALL_MANIFEST) && \
	if [ -e '$(BAREBOX)' ]; then \
		cp $(BAREBOX) $(BINARIES_DIR)/loader.img && \
		cp $(BAREBOX_SIG) $(BINARIES_DIR)/loader.sig; \
	fi && \
	if [ -e '$(ULOADER)' ]; then \
		cp $(ULOADER) $(BINARIES_DIR)/uloader.img && \
		cp $(ULOADER_SIG) $(BINARIES_DIR)/uloader.sig; \
	fi && \
	if [ -e '$(BRUNO_LOADER)' ]; then \
		cp -f $(BRUNO_LOADER) $(BINARIES_DIR)/loader.img && \
		cp -f $(BRUNO_LOADER_SIG) $(BINARIES_DIR)/loader.sig; \
	fi && \
	if [ '$(BRUNO_SIGNING)' = 'y' ]; then \
		gzip -c <$(BINARIES_DIR)/vmlinux \
			>$(BINARIES_DIR)/vmlinuz_unsigned && \
		chmod 0644 $(BINARIES_DIR)/vmlinuz_unsigned && \
		cp $(BINARIES_DIR)/vmlinuz_unsigned $(BINARIES_DIR)/vmlinuz && \
		( \
			export LD_PRELOAD=; $(call HOST_GOOGLE_SIGNING_SIGN); \
		); \
	fi && \
	cd $(BINARIES_DIR) && \
	if [ '$(BR2_TARGET_ROOTFS_SQUASHFS)' = 'y' ]; then \
		ln -f rootfs.squashfs rootfs.img && \
		if [ '$(BR2_TARGET_ROOTFS_RECOVERYFS)' != 'y' ]; then \
			$(shell echo $(INITRAMFS_COMPRESS_COMMAND)) <simpleramfs.cpio >$(INITRAMFS_IMAGE); \
		else \
			$(shell echo $(INITRAMFS_COMPRESS_COMMAND)) <recoveryfs.cpio >$(INITRAMFS_IMAGE); \
		fi; \
	fi && \
	if [ '$(BUILD_UIMAGE)' = 'y' ]; then \
		$(HOST_DIR)/usr/bin/mkimage \
			-A $(BR2_ARCH) -O linux -T $(MKIMAGE_IMAGE_TYPE) -C $(MKIMAGE_COMPRESSION_TYPE) \
			-a $(MKIMAGE_KERNEL_LOAD_ADDRESS) -e $(MKIMAGE_KERNEL_ENTRY_POINT) -n Linux \
			-d $(MKIMAGE_DATA_FILE) \
			$(MKIMAGE_EXTRA_FLAGS) \
			uImage && \
		chmod a+r uImage && \
		( \
			if [ '$(OPTIMUS_SIGNING)' = 'y' ]; then \
				if [ '$(BR2_TARGET_ROOTFS_RECOVERYFS)' = 'y' ]; then \
					if [ '$(BR2_HAVE_EXTRA_CLEANUP)' != 'y' ]; then \
						echo 'Signing recovery kernel with recovery private key'; \
						export LD_PRELOAD=; $(call HOST_GOOGLE_SIGNING_OPTIMUS_RECOVERY_SIGN,uImage); \
					else \
						echo 'Signing emergency kernel with Optimus private key'; \
						export LD_PRELOAD=; $(call HOST_GOOGLE_SIGNING_OPTIMUS_KERNEL_SIGN,uImage); \
					fi \
				else \
					echo 'Signing kernel with Optimus private key' && \
					export LD_PRELOAD=; $(call HOST_GOOGLE_SIGNING_OPTIMUS_KERNEL_SIGN,uImage); \
				fi \
			fi \
		); \
	fi && \
	if [ '$(BRUNOv2_SIGNING)' = 'y' ]; then \
		cp $(BINARIES_DIR)/zImage $(BINARIES_DIR)/zImage_unsigned && \
		( \
			export LD_PRELOAD=; $(call HOST_BRUNOv2_SIGNING_SIGN,\
									$(BINARIES_DIR)/zImage,\
									$(BINARIES_DIR)/$(ROOTFS_GINSTALL_KERNEL_FILE)); \
		); \
	fi && \
	ln -f $(ROOTFS_GINSTALL_KERNEL_FILE) kernel.img && \
	( \
		if [ -n '$(ROOTFS_GINSTALL_FILESYSTEM_FILE)' ]; then \
			echo -n 'rootfs.img-sha1: ' && sha1sum rootfs.img | cut -c1-40; \
		fi; \
		echo -n 'kernel.img-sha1: ' && sha1sum kernel.img | cut -c1-40 && \
		if [ -n '$(BRUNO_LOADER)' ]; then \
		  echo -n 'loader.img-sha1: ' && sha1sum loader.img | cut -c1-40 && \
		  echo -n 'loader.sig-sha1: ' && sha1sum loader.sig | cut -c1-40; \
		fi ) >>$(ROOTFS_GINSTALL_MANIFEST) && \
	tar -cf '$(value ROOTFS_GINSTALL_VERSION).gi' \
		$(ROOTFS_GINSTALL_MANIFEST) \
		$(BRUNO_LOADERS_V3_V4) \
		kernel.img \
		$(ROOTFS_GINSTALL_FILESYSTEM_FILE) && \
	ln -sf '$(value ROOTFS_GINSTALL_VERSION).gi' latest.gi;
endef

# v2 image format was used at launch of GFiber TV devices.
# it contains only a version file, and no provision for
# specifying platform compatibility
define ROOTFS_GINSTALL_CMD_V2
	set -e; \
	if [ '$(BR2_LINUX_KERNEL_VMLINUX)' = 'y' ]; then \
		gzip -c <$(BINARIES_DIR)/vmlinux \
			>$(BINARIES_DIR)/vmlinuz_unsigned && \
		chmod 0644 $(BINARIES_DIR)/vmlinuz_unsigned && \
		if [ -e '$(BRUNO_LOADER)' ]; then \
			cp -f $(BRUNO_LOADER) $(BINARIES_DIR)/loader.bin && \
			cp -f $(BRUNO_LOADER_SIG) $(BINARIES_DIR)/loader.sig; \
		fi && \
		cp $(BINARIES_DIR)/vmlinuz_unsigned $(BINARIES_DIR)/vmlinuz && \
		( \
			export LD_PRELOAD=; $(call HOST_GOOGLE_SIGNING_SIGN); \
		); \
	fi && \
	cd $(BINARIES_DIR) && \
	$(shell echo $(INITRAMFS_COMPRESS_COMMAND)) <simpleramfs.cpio >$(INITRAMFS_IMAGE) && \
	tar -cf $(value ROOTFS_GINSTALL_VERSION).gi \
		version \
		$(BRUNO_LOADERS_V2) \
		vmlinuz \
		rootfs.squashfs && \
	ln -sf '$(value ROOTFS_GINSTALL_VERSION).gi' latest.gi
endef

ifeq ($(BR2_TARGET_ROOTFS_GINSTALL_V3)$(BR2_TARGET_ROOTFS_GINSTALL_V4),y)
ROOTFS_GINSTALL_CMD=$(ROOTFS_GINSTALL_CMD_V3_V4)
else
ROOTFS_GINSTALL_CMD=$(ROOTFS_GINSTALL_CMD_V2)
endif

$(eval $(call ROOTFS_TARGET,ginstall))
