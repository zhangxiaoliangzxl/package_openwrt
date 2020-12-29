#
# Copyright (C) 2016 ysprogram@163.com
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
# 
# description: this program is wireless data frame sniff
#

include $(TOPDIR)/rules.mk

PKG_NAME:=cscan
PKG_VERSION:=5.4
PKG_RELEASE:=12

#PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
#PKG_SOURCE_URL:=http://192.168.23.188/package/ar71xx/

PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME)
	SECTION:=airocov
	CATEGORY:=airocov
	DEPENDS:=+libcurl +libjson-c +libnl +libnl-tiny
	MAINTAINER:=shizhai <ysprogram@163.com>
	TITLE:=802.11 Radio custom Scanning Tool based on horst
endef

define Package/$(PKG_NAME)/description
	[ cscan ] is a scanning and analysis tool for 802.11 wireless networks
	and collect mac of machine which associate with the network.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)
endef

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/cscan $(1)/usr/sbin/
	$(INSTALL_DIR) $(1)/etc
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/cscan.conf $(1)/etc/
	$(INSTALL_DIR) $(1)
	$(CP) ./files/* $(1)/
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
