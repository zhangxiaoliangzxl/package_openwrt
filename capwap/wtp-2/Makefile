#
# Copyright (C) 2011-2014 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=wtp-2
PKG_RELEASE:=1
MODEL_NAME:=capwap
PKG_BUILD_DIR:=$(BUILD_DIR)/$(MODEL_NAME)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME)
  SECTION:=$(PKG_NAME)
  CATEGORY:=capwap modules
  TITLE:=capwap control module(2 tunnel version)
  MAINTAINER:=Jo-Philipp Wich <xm@subsignal.org>
  DEPENDS:=+libpthread +libopenssl
endef

define Package/$(PKG_NAME)/description
 This package contains the small usbreset utility which
 can be used to send a USB port reset to a USB device -
 useful for debugging or to force re-detection of particular
 devices.
endef

define Build/Prepare
	rm -rf $(PKG_BUILD_DIR)
	mkdir -p $(PKG_BUILD_DIR)/files/
	mkdir -p $(PKG_BUILD_DIR)/init.d/
	\$(CP) ./src/* $(PKG_BUILD_DIR)/
	\$(CP) ./files/* $(PKG_BUILD_DIR)/files
	\$(CP) ./init.d/* $(PKG_BUILD_DIR)/init.d
endef

#define Build/Compile
#endef

#define Package/$(PKG_NAME)/postinst
#	if [ `uci get system.@system[-1].apmode` -eq 0 ];then /etc/init.d/WTP disable;fi
#endef

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/usr/capwap
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/WTP $(1)/usr/capwap/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/files/* $(1)/usr/capwap/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/init.d/WTP $(1)/etc/init.d/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/files/wtp.cfg $(1)/etc/config/wtp
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
