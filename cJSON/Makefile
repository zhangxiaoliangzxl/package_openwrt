#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
# https://github.com/DaveGamble/cJSON.git
#

include $(TOPDIR)/rules.mk

PKG_NAME:=cJSON
PKG_VERSION:=1.7.14
PKG_RELEASE:=1
PKG_MAINTAINER:=DaveGamble

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/DaveGamble/cJSON.git
PKG_MIRROR_HASH:=fb50a663eefdc76bafa80c82bc045af13b1363e8f45cec8b442007aef6a41343
PKG_SOURCE_VERSION:=d2735278ed1c2e4556f53a7a782063b31331dbf7
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)

PKG_LICENSE:=MIT
PKG_LICENSE_FILES:=LICENSE

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

define Package/cJSON
	SECTION:=net
	CATEGORY:=Network
	TITLE:=cJSON
	URL:=https://github.com/DaveGamble
endef

define Package/cJSON/description
	Ultralightweight JSON parser in ANSI C.
endef
#cmake 参数
CMAKE_OPTIONS += -DENABLE_CJSON_UTILS=On \
				 -DENABLE_CJSON_TEST=Off \
				 -DCMAKE_INSTALL_PREFIX=/usr

define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/include
	$(CP) $(PKG_INSTALL_DIR)/usr/include/cjson $(1)/usr/include/
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libcjson.so* $(1)/usr/lib/
endef

define Package/cJSON/install
	#$(INSTALL_DIR) $(1)/usr/bin
	#$(INSTALL_BIN) $(PKG_BUILD_DIR)/cJSON_test $(1)/usr/bin
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libcjson.so.* $(1)/usr/lib/
	#$(CP) $(PKG_INSTALL_DIR)/usr/lib/libcjson_utils.so.* $(1)/usr/lib/
endef

$(eval $(call BuildPackage,cJSON))
