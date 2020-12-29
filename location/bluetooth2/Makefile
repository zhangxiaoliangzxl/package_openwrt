include $(TOPDIR)/rules.mk
#Name and release number of this package
PKG_NAME:=bluetooth2
PKG_RELEASE:=1.5

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)
include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME)
	SECTION:=airocov
	CATEGORY:=airocov
	DEPENDS:=+libcurl +libpthread +libuci
	TITLE:=$(PKG_NAME) Program for test openssl
endef

define Package/$(PKG_NAME)/description
	the software is to protect some useful program
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)
endef

define Package/$(PKG_NAME)/config
	source "$(SOURCE)/config.in"
endef

ifeq ($(CONFIG_TARGET_ar71xx_generic_airocov_9531), y)
	BLUE_CONFIG:=9531
else ifeq ($(CONFIG_PACKAGE_bluetooth2_only), y)
	BLUE_CONFIG:=only
else ifeq ($(CONFIG_PACKAGE_bluetooth2_coexistence), y)
	BLUE_CONFIG:=coexistence
endif

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/$(PKG_NAME) $(1)/usr/sbin/
	$(CP) files/* $(1)
	@if [ "$(BLUE_CONFIG)" == "9531" ];then \
	    mv $(1)/etc/config/blconfig_9531 $(1)/etc/config/blconfig; \
	    rm $(1)/etc/config/blconfig_*; \
	elif [ "$(BLUE_CONFIG)" == "only" ];then \
	    mv $(1)/etc/config/blconfig_only $(1)/etc/config/blconfig; \
	    rm $(1)/etc/config/blconfig_*; \
    elif [ "$(BLUE_CONFIG)" == "coexistence" ];then \
	    mv $(1)/etc/config/blconfig_coexistence $(1)/etc/config/blconfig; \
	    rm $(1)/etc/config/blconfig_*; \
	fi
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
