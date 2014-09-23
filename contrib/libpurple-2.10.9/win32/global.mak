#
# global.mak
#
# This file should be included by all Makefile.mingw files for project
# wide definitions (after correctly defining PIDGIN_TREE_TOP).
#

#include optional $(PIDGIN_TREE_TOP)/local.mak to allow overriding of any definitions
-include $(PIDGIN_TREE_TOP)/local.mak

# Locations of our various dependencies
WIN32_DEV_TOP ?= $(PIDGIN_TREE_TOP)/../win32-dev
GTKSPELL_TOP ?= $(WIN32_DEV_TOP)/gtkspell-2.0.16
ENCHANT_TOP ?= $(WIN32_DEV_TOP)/enchant_1.6.0_win32
GTK_TOP ?= $(WIN32_DEV_TOP)/gtk_2_0-2.14
GTK_BIN ?= $(GTK_TOP)/bin
BONJOUR_TOP ?= $(WIN32_DEV_TOP)/Bonjour_SDK
LIBXML2_TOP ?= $(WIN32_DEV_TOP)/libxml2-2.9.0
MEANWHILE_TOP ?= $(WIN32_DEV_TOP)/meanwhile-1.0.2_daa3
NSS_TOP ?= $(WIN32_DEV_TOP)/nss-3.15.4-nspr-4.10.2
PERL_LIB_TOP ?= $(WIN32_DEV_TOP)/perl-5.10.0
SILC_TOOLKIT ?= $(WIN32_DEV_TOP)/silc-toolkit-1.1.10
TCL_LIB_TOP ?= $(WIN32_DEV_TOP)/tcl-8.4.5
GSTREAMER_TOP ?= $(WIN32_DEV_TOP)/gstreamer-0.10.13
GCC_SSP_TOP ?= $(shell dirname $(shell which $(CC)))
CYRUS_SASL_TOP ?= $(WIN32_DEV_TOP)/cyrus-sasl-2.1.25

# Where we installing this stuff to?
PIDGIN_INSTALL_DIR := $(PIDGIN_TREE_TOP)/win32-install-dir
PURPLE_INSTALL_DIR := $(PIDGIN_TREE_TOP)/win32-install-dir
PIDGIN_INSTALL_PLUGINS_DIR := $(PIDGIN_INSTALL_DIR)/plugins
PIDGIN_INSTALL_PERL_DIR := $(PIDGIN_INSTALL_PLUGINS_DIR)/perl
PURPLE_INSTALL_PLUGINS_DIR := $(PURPLE_INSTALL_DIR)/plugins
PURPLE_INSTALL_PERL_DIR := $(PURPLE_INSTALL_PLUGINS_DIR)/perl
PURPLE_INSTALL_PO_DIR := $(PURPLE_INSTALL_DIR)/locale

# Important (enough) locations in our source code
PURPLE_TOP := $(PIDGIN_TREE_TOP)/libpurple
PURPLE_PLUGINS_TOP := $(PURPLE_TOP)/plugins
PURPLE_PERL_TOP := $(PURPLE_PLUGINS_TOP)/perl
PIDGIN_TOP := $(PIDGIN_TREE_TOP)/pidgin
PIDGIN_PIXMAPS_TOP := $(PIDGIN_TOP)/pixmaps
PIDGIN_PLUGINS_TOP := $(PIDGIN_TOP)/plugins
PURPLE_PO_TOP := $(PIDGIN_TREE_TOP)/po
PURPLE_PROTOS_TOP := $(PURPLE_TOP)/protocols

# Locations of important (in-tree) build targets
PIDGIN_CONFIG_H := $(PIDGIN_TREE_TOP)/config.h
PURPLE_CONFIG_H := $(PIDGIN_TREE_TOP)/config.h
PIDGIN_REVISION_H := $(PIDGIN_TREE_TOP)/package_revision.h
PIDGIN_REVISION_RAW_TXT := $(PIDGIN_TREE_TOP)/package_revision_raw.txt
PURPLE_PURPLE_H := $(PURPLE_TOP)/purple.h
PURPLE_VERSION_H := $(PURPLE_TOP)/version.h
PURPLE_DLL := $(PURPLE_TOP)/libpurple.dll
PURPLE_PERL_DLL := $(PURPLE_PERL_TOP)/perl.dll
PIDGIN_DLL := $(PIDGIN_TOP)/pidgin.dll
PIDGIN_EXE := $(PIDGIN_TOP)/pidgin.exe
PIDGIN_PORTABLE_EXE := $(PIDGIN_TOP)/pidgin-portable.exe

GCCWARNINGS ?= -Waggregate-return -Wcast-align -Wdeclaration-after-statement -Werror-implicit-function-declaration -Wextra -Wno-sign-compare -Wno-unused-parameter -Winit-self -Wmissing-declarations -Wmissing-prototypes -Wnested-externs -Wpointer-arith -Wundef

CC_HARDENING_OPTIONS ?= -Wstack-protector -fwrapv -fno-strict-overflow -Wno-missing-field-initializers -Wformat-security -fstack-protector-all --param ssp-buffer-size=1
LD_HARDENING_OPTIONS ?= -Wl,--dynamicbase -Wl,--nxcompat


# parse the version number from the configure.ac file if it is newer
#m4_define([purple_major_version], [2])
#m4_define([purple_minor_version], [0])
#m4_define([purple_micro_version], [0])
#m4_define([purple_version_suffix], [devel])
PIDGIN_VERSION := $(shell \
  if [ ! $(PIDGIN_TREE_TOP)/VERSION -nt $(PIDGIN_TREE_TOP)/configure.ac ]; then \
    awk 'BEGIN {FS="[\\(\\)\\[\\]]"} /^m4_define..purple_(major|minor)_version/ {printf("%s.",$$5);} /^m4_define..purple_micro_version/ {printf("%s",$$5);} /^m4_define..purple_version_suffix/ {printf("%s",$$5); exit}' \
      $(PIDGIN_TREE_TOP)/configure.ac > $(PIDGIN_TREE_TOP)/VERSION; \
  fi; \
  cat $(PIDGIN_TREE_TOP)/VERSION \
)
PURPLE_VERSION := $(PIDGIN_VERSION)
ifdef EXTRAVERSION
DISPLAY_VERSION := $(PIDGIN_VERSION)-$(EXTRAVERSION)
else
DISPLAY_VERSION := $(PIDGIN_VERSION)
endif

CYRUS_SASL ?= 1

ifeq ($(CYRUS_SASL), 1)
DEFINES += -DHAVE_CYRUS_SASL
endif

DEFINES += -DHAVE_CONFIG_H -DWIN32_LEAN_AND_MEAN

CFLAGS += -O2 -Wall $(GCCWARNINGS) $(CC_HARDENING_OPTIONS) -pipe -mms-bitfields -g

# If not specified, dlls are built with the default base address of 0x10000000.
# When loaded into a process address space a dll will be rebased if its base
# address colides with the base address of an existing dll.  To avoid rebasing 
# we do the following.  Rebasing can slow down the load time of dlls and it
# also renders debug info useless.
DLL_LD_FLAGS += -Wl,--enable-auto-image-base -Wl,--enable-auto-import $(LD_HARDENING_OPTIONS) -lssp

# Build programs
ifeq "$(origin CC)" "default"
  CC := gcc.exe
endif
GMSGFMT ?= $(WIN32_DEV_TOP)/gettext-0.17/bin/msgfmt
MAKENSIS ?= makensis.exe
PERL ?= perl
WINDRES ?= windres
STRIP ?= strip
INTLTOOL_MERGE ?= $(WIN32_DEV_TOP)/intltool_0.40.4-1_win32/bin/intltool-merge
MONO_SIGNCODE ?= signcode
GPG_SIGN ?= gpg

PIDGIN_COMMON_RULES := $(PURPLE_TOP)/win32/rules.mak
PIDGIN_COMMON_TARGETS := $(PURPLE_TOP)/win32/targets.mak
MINGW_MAKEFILE := Makefile.mingw

INSTALL_PIXMAPS ?= 1
INSTALL_SSL_CERTIFICATES ?= 1
