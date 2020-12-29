#
# Copyright (C) 2011 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=libnanopb
PKG_VERSION:=0.4.4
PKG_RELEASE:=1

PKG_SOURCE:=nanopb-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://codeload.github.com/nanopb/nanopb/tar.gz/$(PKG_VERSION)
PKG_HASH:=66621e896c1e357d21b4e5bcc87584afd95abe18ea7a3314ce2696048ab340db
PKG_BUILD_DIR:=$(BUILD_DIR)/nanopb-$(PKG_VERSION)
HOST_BUILD_DIR:=$(BUILD_DIR_HOST)/nanopb-$(PKG_VERSION)

PKG_MAINTAINER:=PetteriAimonen <PetteriAimonen@gmail.com>
PKG_LICENSE:=BSD-2c

PKG_BUILD_DEPENDS:=protobuf/host
HOST_BUILD_DEPENDS:=protobuf/host

PKG_INSTALL:=1
PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/host-build.mk
include $(INCLUDE_DIR)/cmake.mk

define Package/libnanopb
  TITLE:=libnanopb library
  SECTION:=libs
  CATEGORY:=Libraries
  URL:=https://github.com/nanopb/nanopb
endef

define Package/libnanopb/description
  Nanopb is a small code-size Protocol Buffers implementation in ansi C. It is especially suitable for use in microcontrollers, but fits any memory restricted system.
endef

CONFIGURE_ARGS += \
	--enable-shared \
	--enable-static \
	--disable-protoc

define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/include/
	$(CP) $(PKG_INSTALL_DIR)/usr/include/* $(1)/usr/include/
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libprotobuf-nanopb.{a,so*} $(1)/usr/lib/
	#$(INSTALL_DIR) $(1)/usr/lib/pkgconfig
	#$(CP) $(PKG_INSTALL_DIR)/usr/lib/pkgconfig/* $(1)/usr/lib/pkgconfig/
endef

define Package/libnanopb/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libprotobuf-nanopb.so* $(1)/usr/lib/
endef

$(eval $(call BuildPackage,libnanopb))
$(eval $(call HostBuild))

