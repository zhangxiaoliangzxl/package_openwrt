# Kernel module example
include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk
PKG_NAME:=cloud_wlan
PKG_RELEASE:=1
MODEL_NAME:=capwap
PKG_BUILD_DIR:=$(BUILD_DIR)/$(MODEL_NAME)/kmod-$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk
define KernelPackage/$(PKG_NAME)
	SECTION:=kmod-cloud-wlan
	CATEGORY:=capwap modules
#	DEPENDS:=@TARGET_octeon
	TITLE:=Kernel layer capwap function (1 tunnel version )
	AUTOLOAD:=$(call AutoLoad,70,cloud_wlan)
	FILES:=$(PKG_BUILD_DIR)/cloud_wlan.$(LINUX_KMOD_SUFFIX)
endef
define Build/Prepare
	echo $(LINUX_DIR)
	rm -rf $(PKG_BUILD_DIR)
	mkdir -p $(PKG_BUILD_DIR)
	\$(CP) ./src/* $(PKG_BUILD_DIR)
endef
define Build/Compile
	$(MAKE) -C "$(LINUX_DIR)" \
	CROSS_COMPILE="$(TARGET_CROSS)" \
	ARCH="$(LINUX_KARCH)" \
	SUBDIRS="$(PKG_BUILD_DIR)/" \
	$(MAKE_OPTS) \
	EXTRA_CFLAGS="$(BUILDFLAGS)" \
	modules
endef
define Package/$(PKG_NAME)/install
#	$(INSTALL_DIR) $(1)/usr/capwap/
#	$(INSTALL_BIN) $(PKG_BUILD_DIR)/usr/capwap/* $(1)/usr/capwap/
endef
$(eval $(call KernelPackage,$(PKG_NAME)))
