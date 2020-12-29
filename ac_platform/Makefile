
include $(TOPDIR)/rules.mk

PKG_NAME:=ac_platform
PKG_RELEASE:=1

define Package/$(PKG_NAME)
	SECTION:=airocov
	CATEGORY:=airocov
	DEPENDS:=+libopenssl +libcurl +libpthread +libuci +curl +uci +ntpclient +wget +cJSON
	#+STM32upgrade
	TITLE:=$(PKG_NAME)
endef

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)
include $(INCLUDE_DIR)/package.mk
#use cmake
#include $(INCLUDE_DIR)/cmake.mk

define Package/$(PKG_NAME)/description
	the software of CovOS Router to control
endef

DATE_COM=$(shell date)

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)
endef

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/$(PKG_NAME) $(1)/usr/sbin/
	$(INSTALL_DIR) $(1)
	$(CP) ./files/* $(1)/
	echo $(DATE_COM) > $(1)/etc/config/ac_version
	echo $(PKG_NAME) V1R$(PKG_RELEASE) >> $(1)/etc/config/ac_version
	#$(RM) -rf $(1)/etc/config/aconf
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
