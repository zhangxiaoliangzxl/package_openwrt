#
# Copyright (C) 2008 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=netlink_notify
PKG_RELEASE:=1

###kernel mod

define KernelPackage/$(PKG_NAME)/Default
	SUBMENU:=Other modules
	TITLE:=Module for netlink notify
	AUTOLOAD:=$(call AutoLoad,10,netlink_notify)
	FILES:=$(PKG_BUILD_DIR)/netlink_notify.ko
	KCONFIG:=
endef

define KernelPackage/$(PKG_NAME)
  $(call KernelPackage/$(PKG_NAME)/Default)
endef

define KernelPackage/$(PKG_NAME)/Default/description
Module for netlink notify
endef

define KernelPackage/$(PKG_NAME)/description
$(call KernelPackage/$(PKG_NAME)/Default/description)
endef

###user app

define Package/app_netlink_notify
	SECTION:=airocov
	CATEGORY:=airocov
 	TITLE:=user app for netlink notify
#DEPENDS:=+kmod-netlink_notify
endef

define Package/app_netlink_notify/description
user app for netlink notify mod
endef

define Build/Compile/app_netlink_notify
	$(TARGET_CC) -o $(PKG_BUILD_DIR)/netlink_notify_app \
	$(PKG_BUILD_DIR)/user_app/netlink_notify_app.c
endef

define Package/app_netlink_notify/install
	$(INSTALL_DIR) $(1)/usr/sbin
	#$(INSTALL_BIN) $(PKG_BUILD_DIR)/netlink_notify_app $(1)/usr/sbin
	$(INSTALL_BIN) files/netlink_notify_fix.sh $(1)/usr/sbin/netlink_notify_check
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) files/netlink_notify_fix.init $(1)/etc/init.d/netlink_notify
endef

####################################################################
EXTRA_CFLAGS:= \
	$(patsubst CONFIG_%, -DCONFIG_%=1, $(patsubst %=m,%,$(filter %=m,$(EXTRA_KCONFIG)))) \
	$(patsubst CONFIG_%, -DCONFIG_%=1, $(patsubst %=y,%,$(filter %=y,$(EXTRA_KCONFIG)))) \
 
MAKE_OPTS:= \
	ARCH="$(LINUX_KARCH)" \
	CROSS_COMPILE="$(TARGET_CROSS)" \
	SUBDIRS="$(PKG_BUILD_DIR)" \
	EXTRA_CFLAGS="$(EXTRA_CFLAGS)" \
	$(EXTRA_KCONFIG)
 
define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
	$(CP) ./user_app $(PKG_BUILD_DIR)/
endef

define Build/Compile/kmod
	$(MAKE) -C "$(LINUX_DIR)" \
	$(MAKE_OPTS) \
	modules
endef


define Build/Compile
	$(Build/Compile/kmod)
	$(if $(CONFIG_PACKAGE_app_netlink_notify),$(Build/Compile/app_netlink_notify))
endef
	
$(eval $(call KernelPackage,$(PKG_NAME)))
$(eval $(call BuildPackage,app_netlink_notify))
