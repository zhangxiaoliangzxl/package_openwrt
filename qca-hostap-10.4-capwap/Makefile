
include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG:=qca-hostap
PKG_NAME:=$(PKG)-10.4-capwap
PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=ssh://qca-git01.qualcomm.com:29418/wifi/$(PKG_NAME).git
PKG_BRANCH:=master
PKG_RELEASE:=1

PATCH_DIR:=$(TOPDIR)/qca/src/$(PKG_NAME)/qca-patches
include $(INCLUDE_DIR)/local-development.mk
ifeq ($(DUMP)$(PKG_VERSION),)
  PKG_REV:=$(shell git ls-remote $(PKG_SOURCE_URL) $(PKG_BRANCH) | cut -b -7)
  PKG_VERSION:=g$(PKG_REV)
endif

LOCAL_TYPE=$(strip \
		$(if $(findstring supplicant,$(BUILD_VARIANT)),supplicant, \
		hostap \
	))

LOCAL_VARIANT=$(patsubst supplicant-%,%,$(BUILD_VARIANT))

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(BUILD_VARIANT)/$(PKG)-$(PKG_VERSION)

WIFI_10_4_U:=PACKAGE_kmod-qca-wifi-10.4-unified-profile
WIFI_10_4_A:=PACKAGE_kmod-qca-wifi-10.4-akronite-perf
WIFI_10_4_D:=PACKAGE_kmod-qca-wifi-10.4-dakota-perf
WIFI_10_4_MIPS:=PACKAGE_kmod-qca-wifi-10.4-perf
WIFI_10_2_MIPS:=PACKAGE_kmod-qca-wifi-perf
WIFI_10_2_ARM:=PACKAGE_kmod-qca-wifi-akronite-perf
WIFI_10_4_MIPS_UNIFIED:=PACKAGE_kmod-qca-wifi-10.4-unified-perf
WIFI_10_4_MIPS_LOWMEM:=PACKAGE_kmod-qca-wifi-10.4-lowmem-profile
#WIFI_PKGS:=$(WIFI_10_4_U)||$(WIFI_10_4_A)||$(WIFI_10_4_D)||$(WIFI_10_4_MIPS)||$(WIFI_10_2_MIPS)||$(WIFI_10_2_ARM)||$(WIFI_10_4_MIPS_UNIFIED)||$(WIFI_10_4_MIPS_LOWMEM)
#PKG_BUILD_DEPENDS:=$(WIFI_10_4_U):qca-wifi-10.4 $(WIFI_10_4_A):qca-wifi-10.4 $(WIFI_10_4_D):qca-wifi-10.4 \
	$(WIFI_10_2_MIPS):qca-wifi $(WIFI_10_2_ARM):qca-wifi $(WIFI_10_4_MIPS):qca-wifi-10.4 \
	$(WIFI_10_4_MIPS_UNIFIED):qca-wifi-10.4 $(WIFI_10_4_MIPS_LOWMEM):qca-wifi-10.4
WIFI_PKGS:=kmod-qca-wifi-10.4
PKG_BUILD_DEPENDS:=qca-wifi-10.4

include $(INCLUDE_DIR)/package-version-override.mk
include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME)/Default
  SECTION:=QCA
  CATEGORY:=QCA Proprietary software
  URL:=http://www.qca.qualcomm.com
  MAINTAINER:=Qualcomm Atheros
endef

define Package/$(PKG_NAME)
  $(call Package/$(PKG_NAME)/Default)
  TITLE:=Hostap authenticator
  DEPENDS:=@$(WIFI_PKGS) @(!(PACKAGE_hostapd)) +libnl
  VARIANT:=default
endef

define Package/$(PKG_NAME)/description
 This package contains the IEEE 802.1x/WPA/EAP/RADIUS Authenticator.
endef

define Package/qca-hostapd-cli-10.4-capwap
  $(call Package/$(PKG_NAME)/Default)
  DEPENDS:=$(PKG_NAME) +librt
  TITLE:=Hostap authenticator command line interface
endef

define Package/qca-hostapd-cli-10.4-capwap/description
 This package contains a command line utility to control the
 IEEE 802.1x/WPA/EAP/RADIUS Authenticator.
endef



ifneq ($(wildcard $(PKG_BUILD_DIR)/.config_*),$(subst .configured_,.config_,$(STAMP_CONFIGURED)))
  define Build/Configure/rebuild
	$(FIND) $(PKG_BUILD_DIR) -name \*.o -or -name \*.a | $(XARGS) rm -f
	rm -f $(PKG_BUILD_DIR)/hostapd/hostapd
	rm -f $(PKG_BUILD_DIR)/wpa_supplicant/wpa_supplicant
	rm -f $(PKG_BUILD_DIR)/.config_*
	touch $(subst .configured_,.config_,$(STAMP_CONFIGURED))
  endef
endif


define Package/$(PKG_NAME)/config

endef

define Build/Configure
	$(Build/Configure/rebuild)
	$(if $(wildcard ./files/hostapd-$(LOCAL_VARIANT).config), \
		$(CP) ./files/hostapd-$(LOCAL_VARIANT).config $(PKG_BUILD_DIR)/hostapd/.config \
	)
	$(CP) ./files/wpa_supplicant-10.4-$(LOCAL_VARIANT).config $(PKG_BUILD_DIR)/wpa_supplicant/.config
ifeq ($(findstring 4.4, $(LINUX_VERSION)),)
ifeq ($(LOCAL_VARIANT),default)
	echo "CONFIG_NO_LINUX_PACKET_SOCKET_WAR=y" >> $(PKG_BUILD_DIR)/wpa_supplicant/.config
endif
endif
endef

TARGET_CPPFLAGS += \
	-I$(STAGING_DIR)/usr/include \
	-I$(STAGING_DIR)/usr/include/qca-nss-macsec

TARGET_LDFLAGS += -L$(STAGING_DIR)/usr/lib

TARGET_LDFLAGS += \
	-lnl-3 -lnl-genl-3 -lm

ifneq ($(LOCAL_TYPE),hostap)
    TARGET_LDFLAGS += \
		-lssl -lcrypto
  ifeq ($(LOCAL_VARIANT),macsec)
    TARGET_LDFLAGS += -lfal 
  endif
endif

define Build/RunMake
	CFLAGS="$(TARGET_CPPFLAGS) $(TARGET_CFLAGS)" \
	$(MAKE) -C $(PKG_BUILD_DIR)/$(1) \
	$(TARGET_CONFIGURE_OPTS) \
	LIBS="$(TARGET_LDFLAGS)" \
	$(2)
endef

define Build/Compile/qca-hostap
	$(call Build/RunMake,hostapd, \
		hostapd hostapd_cli \
	)
endef


define Build/Compile
	$(Build/Compile/qca-$(LOCAL_TYPE))
endef

define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/include
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_BUILD_DIR)/src/common/wpa_ctrl.h $(1)/usr/include/
	$(CP) $(PKG_BUILD_DIR)/src/common/ieee802_11_defs.h $(1)/usr/include/
	$(CP) $(PKG_BUILD_DIR)/src/utils/includes.h $(1)/usr/include/
	$(CP) $(PKG_BUILD_DIR)/src/utils/build_config.h $(1)/usr/include/
	$(CP) $(PKG_BUILD_DIR)/src/utils/eloop.h $(1)/usr/include/
	$(CP) $(PKG_BUILD_DIR)/src/utils/os.h $(1)/usr/include/
	$(CP) $(PKG_BUILD_DIR)/src/utils/common.h $(1)/usr/include/
	$(CP) $(PKG_BUILD_DIR)/src/utils/wpa_debug.h $(1)/usr/include/
	$(CP) $(PKG_BUILD_DIR)/src/utils/wpabuf.h $(1)/usr/include/
	$(CP) $(PKG_BUILD_DIR)/src/drivers/linux_ioctl.h $(1)/usr/include/
	$(CP) $(PKG_BUILD_DIR)/src/drivers/linux_wext.h $(1)/usr/include/
	$(CP) $(PKG_BUILD_DIR)/src/drivers/netlink.h $(1)/usr/include/
	$(CP) $(PKG_BUILD_DIR)/src/drivers/priv_netlink.h $(1)/usr/include/
	$(CP) $(PKG_BUILD_DIR)/src/common/wpa_ctrl.o $(1)/usr/lib/
	$(CP) $(PKG_BUILD_DIR)/src/drivers/netlink.o $(1)/usr/lib/
	$(CP) $(PKG_BUILD_DIR)/src/utils/eloop.o $(1)/usr/lib/
	$(CP) $(PKG_BUILD_DIR)/src/utils/wpa_debug.o $(1)/usr/lib/
	$(CP) $(PKG_BUILD_DIR)/src/utils/common.o $(1)/usr/lib/
	$(CP) $(PKG_BUILD_DIR)/src/utils/os_unix.o $(1)/usr/lib/
endef

define Install/$(PKG_NAME)
	$(INSTALL_DIR) $(1)/lib/wifi
	$(INSTALL_DATA) ./files/hostapd.sh $(1)/lib/wifi/hostapd.sh
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/qca-hostapd.init $(1)/etc/init.d/qca-hostapd
	$(INSTALL_DIR) $(1)/usr/sbin
endef


define Package/$(PKG_NAME)/install
	$(call Install/$(PKG_NAME),$(1))
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/hostapd/hostapd $(1)/usr/sbin/
endef

define Package/qca-hostapd-cli-10.4-capwap/install
	$(INSTALL_DIR) $(1)/usr/sbin $(1)/etc/hotplug.d/button
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/hostapd/hostapd_cli $(1)/usr/sbin/
	#$(INSTALL_DATA) ./files/wps-hotplug.sh $(1)/etc/hotplug.d/button/50-wps
	#$(INSTALL_DATA) ./files/wps-extender-hotplug.sh \
			#$(1)/etc/hotplug.d/button/54-wps-extender
	#$(INSTALL_DATA) ./files/wps-reset-hotplug.sh $(1)/etc/hotplug.d/button/51-wps-reset

	$(INSTALL_DIR) $(1)/lib/wifi
	$(INSTALL_BIN) ./files/wps-hostapd-update-uci.sh \
			$(1)/lib/wifi/wps-hostapd-update-uci

	$(INSTALL_BIN) ./files/wps-hostapd-nbh-update.sh \
			$(1)/lib/wifi/wps-hostapd-nbh-update
  endef


$(eval $(call BuildPackage,$(PKG_NAME)))
$(eval $(call BuildPackage,qca-hostapd-cli-10.4-capwap))
