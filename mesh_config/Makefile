#
# Copyright (C) 2015 OpenWrt-dist
#
# This is free software, licensed under the GNU General Public License v3.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=mesh_default
PKG_VERSION:=1.0
PKG_RELEASE:=1

PKG_LICENSE:=GPLv3
PKG_LICENSE_FILES:=LICENSE
PKG_MAINTAINER:=zxl <zxl@163.com>

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME)
	SECTION:=airocov
	CATEGORY:=airocov
	TITLE:=mesh configuration
	PKGARCH:=all
endef

define Package/$(PKG_NAME)/description
	mesh default configuration
endef

define Build/Prepare
endef

define Build/Configure
endef

define Build/Compile
endef

define Package/$(PKG_NAME)/postinst
endef

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_BIN) ./files/root/etc/uci-defaults/zzz-meshap $(1)/etc/uci-defaults/zzz-meshap
	$(INSTALL_BIN) ./files/root/etc/uci-defaults/zzz-meshbatman $(1)/etc/uci-defaults/zzz-meshbatman
	
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_BIN) ./files/root/etc/config/network $(1)/etc/config/network
	$(INSTALL_BIN) ./files/root/etc/config/wireless $(1)/etc/config/wireless
	$(INSTALL_BIN) ./files/root/etc/config/dhcp $(1)/etc/config/dhcp
	$(INSTALL_BIN) ./files/root/etc/config/mesh $(1)/etc/config/mesh
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/root/etc/init.d/set_mesh $(1)/etc/init.d/set_mesh
endef


$(eval $(call BuildPackage,$(PKG_NAME)))
