#
# Copyright (C) 2011-2014 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=configbin
PKG_RELEASE:=1
MODEL_NAME:=capwap
PKG_BUILD_DIR:=$(BUILD_DIR)/$(MODEL_NAME)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/configbin
	SECTION:=configbin_tool
	CATEGORY:=capwap modules
	TITLE:=configbin zone configuration tool
endef

define Build/Prepare
	rm -rf $(PKG_BUILD_DIR)
	mkdir -p $(PKG_BUILD_DIR)/
	\$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Package/configbin/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/configbin $(1)/usr/bin
endef

$(eval $(call BuildPackage,configbin))
