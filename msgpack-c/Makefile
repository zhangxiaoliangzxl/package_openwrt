#
# Copyright (C) 2011 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=msgpack
PKG_VERSION:=3.2.0
PKG_RELEASE:=1

PKG_SOURCE:=msgpack-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://github.com/msgpack/msgpack-c/releases/download/cpp-$(PKG_VERSION)
PKG_HASH:=53ae37b760690562a1e1cc03d5e1baa4
PKG_BUILD_DIR:=$(BUILD_DIR)/msgpack-$(PKG_VERSION)
HOST_BUILD_DIR:=$(BUILD_DIR_HOST)/msgpack-$(PKG_VERSION)

PKG_MAINTAINER:=msgpack <http://msgpack.org/>
PKG_LICENSE:=BSD-2c

#PKG_BUILD_DEPENDS:=msgpack/host
#HOST_BUILD_DEPENDS:=msgpack/host

PKG_INSTALL:=1
PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk
include $(INCLUDE_DIR)/host-build.mk

define Package/$(PKG_NAME)
  TITLE:=msgpack c library
  SECTION:=libs
  CATEGORY:=Libraries
  DEPENDS:=+libpthread
  URL:=https://github.com/msgpack/msgpack-c
endef

define Package/$(PKG_NAME)/description
  Runtime library to use msgpack from C applications.
endef

CONFIGURE_ARGS += \
	--enable-shared

define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/include/
	$(CP) $(PKG_INSTALL_DIR)/usr/include/* $(1)/usr/include/
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libmsgpackc.{a,so*} $(1)/usr/lib/
	$(INSTALL_DIR) $(1)/usr/lib/pkgconfig
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/pkgconfig/* $(1)/usr/lib/pkgconfig/
endef

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libmsgpackc.so* $(1)/usr/lib/
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
$(eval $(call HostBuild))

