#
# Copyright (C) 2015 OpenWrt-dist
#
# This is free software, licensed under the GNU General Public License v3.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=local-xinjiang
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
	TITLE:=airocov localization configuration for xinjiang
	PKGARCH:=all
endef

define Package/$(PKG_NAME)/description
	airocov localization configuration for xinjiang
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
	$(INSTALL_BIN) ./files/etc/uci-defaults/xinjiang $(1)/etc/uci-defaults/xinjiang
	$(INSTALL_DIR) $(1)/etc
	$(INSTALL_BIN) ./files/etc/banner_xinjiang $(1)/etc/banner_xinjiang
	$(INSTALL_DIR) $(1)/lib/wifi
	$(INSTALL_BIN) ./files/lib/wifi/qcawifi.sh.xinjiang $(1)/lib/wifi/qcawifi.sh.xinjiang
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) ./files/usr/sbin/factest_xinjiang $(1)/usr/sbin/factest_xinjiang
endef


$(eval $(call BuildPackage,$(PKG_NAME)))
