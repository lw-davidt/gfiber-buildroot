################################################################################
#
# libprojectM
#
################################################################################
LIBPROJECTM_SITE=repo://vendor/opensource/projectM
LIBPROJECTM_DEPENDENCIES=linux bcm_rockford host-pkg-config
LIBPROJECTM_INSTALL_STAGING=YES
LIBPROJECTM_INSTALL_TARGET=YES

LIBPROJECTM_CONF_OPT = -DCMAKE_C_FLAGS="-I$(STAGING_DIR)/usr/include"
LIBPROJECTM_CONF_OPT += -DCMAKE_EXE_LINKER_FLAGS="$(TARGET_LDFLAGS)"
LIBPROJECTM_CONF_OPT += -DUSE_FTGL=NO
LIBPROJECTM_CONF_OPT += -DUSE_OPENMP=NO
LIBPROJECTM_CONF_OPT += -DUSE_GLES1=YES
LIBPROJECTM_CONF_OPT += -DUSE_FBO=NO
LIBPROJECTM_CONF_OPT += -DUSE_NATIVE_GLEW=YES
LIBPROJECTM_CONF_OPT += -DGLEW_NO_GLU=YES
LIBPROJECTM_CONF_OPT += -DINCLUDE-PROJECTM-QT=NO
LIBPROJECTM_CONF_OPT += -DINCLUDE-PROJECTM-PULSEAUDIO=NO
LIBPROJECTM_CONF_OPT += -DINCLUDE-PROJECTM-LIBVISUAL=NO
LIBPROJECTM_CONF_OPT += -DINCLUDE-PROJECTM-TEST=NO

$(eval $(call CMAKETARGETS))
