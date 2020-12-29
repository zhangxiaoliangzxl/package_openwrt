#
# Copyright (C) 2015 OpenWrt-dist
#
# This is free software, licensed under the GNU General Public License v3.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=local-airocov
PKG_VERSION:=1.0
PKG_RELEASE:=1

PKG_LICENSE:=GPLv3
PKG_LICENSE_FILES:=LICENSE
PKG_MAINTAINER:=zxl <zxl@163.com>

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/local-airocov
	SECTION:=airocov
	CATEGORY:=airocov
	TITLE:=airocov localization configuration
	PKGARCH:=all
	DEPENDS:=+luci +luci-i18n-base-zh-cn
endef

define Package/local-airocov/description
	airocov localization configuration
endef

define Build/Prepare
endef

define Build/Configure
endef

define Build/Compile
endef

define Package/local-airocov/postinst
endef

define Package/local-airocov/install
	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_BIN) ./files/root/etc/uci-defaults/local-airocov $(1)/etc/uci-defaults/local-airocov
	$(INSTALL_BIN) ./files/root/etc/uci-defaults/hw_type $(1)/etc/uci-defaults/hw_type
	$(INSTALL_BIN) ./files/root/etc/uci-defaults/build_version $(1)/etc/uci-defaults/build_version
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/root/etc/init.d/set_ip $(1)/etc/init.d/set_ip
	$(INSTALL_BIN) ./files/root/etc/init.d/hostname $(1)/etc/init.d/hostname
	$(INSTALL_DIR) $(1)/etc/hotplug.d/tty
	$(INSTALL_BIN) ./files/root/etc/hotplug.d/tty/00-usbtty $(1)/etc/hotplug.d/tty/00-usbtty
	$(INSTALL_DIR) $(1)/lib/preinit
	$(INSTALL_BIN) ./files/root/lib/preinit/99_00_ttyinit $(1)/lib/preinit/99_00_ttyinit
endef


$(eval $(call BuildPackage,local-airocov))
