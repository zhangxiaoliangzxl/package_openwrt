include $(TOPDIR)/rules.mk

#Name and release number of this package
PKG_NAME:=uwb_v2
PKG_RELEASE:=1.0

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)
include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME)
	SECTION:=airocov
	CATEGORY:=airocov
	DEPENDS:=+libcurl +libpthread +libuci
	# +libprotobuf-c
	TITLE:=$(PKG_NAME) Program for test openssl
endef

define Package/$(PKG_NAME)/description
	the software is to protect some useful program
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
	source "$(SOURCE)/config.in"
endef

ifeq ($(CONFIG_PACKAGE_uwb_only), y)
	UWB_CONFIG:=only
else ifeq ($(CONFIG_PACKAGE_uwb_coexistence), y)
	UWB_CONFIG:=coexistence
endif

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/UWB $(1)/usr/sbin/
	$(CP) files/* $(1)
	@if [ "$(UWB_CONFIG)" == "only" ];then \
	    mv $(1)/etc/config/uwbcon_only $(1)/etc/config/uwbcon; \
	    rm $(1)/etc/config/uwbcon_coexistence; \
	elif [ "$(UWB_CONFIG)" == "coexistence" ];then \
	    mv $(1)/etc/config/uwbcon_coexistence $(1)/etc/config/uwbcon; \
	    rm $(1)/etc/config/uwbcon_only; \
	fi
	#$(RM) -rf $(1)/etc/

endef

$(eval $(call BuildPackage,$(PKG_NAME)))
