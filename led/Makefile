#
# Copyright (C) 2015 OpenWrt-dist
#
# This is free software, licensed under the GNU General Public License v3.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=airocov_led
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
	TITLE:=airocov reg led configuration for xinjiang
	PKGARCH:=all
endef

define Package/$(PKG_NAME)/description
	airocov reg led  configuration for xinjiang
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
	$(INSTALL_DIR) $(1)/usr/sbin
	$(CP) ./files/check_led $(1)/usr/sbin/
	$(CP) ./files/led_check $(1)/usr/sbin/
	$(CP) ./files/airocov_led_on $(1)/usr/sbin/
	$(INSTALL_DIR) $(1)/etc/init.d
	$(CP) ./files/airocov_led $(1)/etc/init.d/
endef


$(eval $(call BuildPackage,$(PKG_NAME)))
