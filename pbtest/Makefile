
include $(TOPDIR)/rules.mk

PKG_NAME:=pbtest
PKG_RELEASE:=1

define Package/$(PKG_NAME)
	SECTION:=airocov
	CATEGORY:=airocov
	DEPENDS:=+libprotobuf-c +PACKAGE_libprotobuf-c
	TITLE:=$(PKG_NAME)
endef

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)
include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME)/description
	pbtest
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)
endef

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/$(PKG_NAME) $(1)/usr/sbin/
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
