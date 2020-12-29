include $(TOPDIR)/rules.mk

#Name and release number of this package
PKG_NAME:=blelink
PKG_RELEASE:=1.0

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)
include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME)
	SECTION:=airocov
	CATEGORY:=airocov
	DEPENDS:=+libpthread +libuci +cJSON
	# +libprotobuf-c
	TITLE:=$(PKG_NAME) Program for airocov
endef

define Package/$(PKG_NAME)/description
	Airocov locaton blelink
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)
	#protoc-c --c_out=$(PKG_BUILD_DIR) uwbDataType.proto
	#mv $(PKG_BUILD_DIR)/uwbDataType.pb-c.c $(PKG_BUILD_DIR)/uwbDataType.c
	#mv $(PKG_BUILD_DIR)/uwbDataType.pb-c.h $(PKG_BUILD_DIR)/uwbDataType.h
	#sed -i 's/uwbDataType.pb-c.h/uwbDataType.h/g' $(PKG_BUILD_DIR)/uwbDataType.c
endef

define Package/$(PKG_NAME)/config
	#source "$(SOURCE)/config.in"
endef

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/$(PKG_NAME) $(1)/usr/sbin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/$(PKG_NAME)test $(1)/usr/sbin/
	$(CP) files/* $(1)
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
