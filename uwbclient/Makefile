include $(TOPDIR)/rules.mk

#Name and release number of this package
PKG_NAME:=uwbclient
PKG_RELEASE:=1.0

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)
include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME)
	SECTION:=airocov
	CATEGORY:=airocov
	DEPENDS:=+socat
	TITLE:=Program for uwb data test
endef

define Package/$(PKG_NAME)/description
	the software is for uwb data test
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)
endef

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/uwbclient $(1)/usr/sbin/
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
