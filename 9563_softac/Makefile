#
# Copyright (C) 2015 OpenWrt-dist
#
# This is free software, licensed under the GNU General Public License v3.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=9563_softac
PKG_VERSION:=1.0
PKG_RELEASE:=1

PKG_LICENSE:=GPLv3
PKG_LICENSE_FILES:=LICENSE
PKG_MAINTAINER:=zxl <zxl@163.com>

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/9563_softac
	SECTION:=airocov
	CATEGORY:=airocov
	DEPENDS:=@PACKAGE_ac_platform
	TITLE:=9563 softac config
	PKGARCH:=all
endef

define Package/9563_softac/description
	9563 softac config
endef

define Build/Prepare
endef

define Build/Configure
endef

define Build/Compile
endef

define Package/9563_softac/postinst
endef

define Package/9563_softac/install
	$(CP) files/* $(1)
endef


$(eval $(call BuildPackage,9563_softac))
