
include $(TOPDIR)/rules.mk

PKG_NAME:=alarm_services
PKG_RELEASE:=1

define Package/$(PKG_NAME)
	SECTION:=airocov
	CATEGORY:=airocov
	DEPENDS:=+libmosquitto +libpthread +cJSON
	#+libopenssl +libpthread +libuci +libjson
	#+STM32upgrade
	TITLE:=$(PKG_NAME)
endef

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)
include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME)/description
	Airocov location alarm services
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)
endef

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/$(PKG_NAME) $(1)/usr/sbin/
	$(INSTALL_BIN) ./files/alarm.pid $(1)/usr/sbin/alarm_pid
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DATA) ./files/alarm.config $(1)/etc/config/alarm
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/alarm.init $(1)/etc/init.d/alarm
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
