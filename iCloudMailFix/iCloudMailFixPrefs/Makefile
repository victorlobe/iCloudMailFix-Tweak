ARCHS = armv7 arm64
TARGET := iphone:7.1

include $(THEOS)/makefiles/common.mk

BUNDLE_NAME = iCloudMailFixPrefs

iCloudMailFixPrefs_FILES = ICMRootListController.m
iCloudMailFixPrefs_FRAMEWORKS = UIKit
iCloudMailFixPrefs_PRIVATE_FRAMEWORKS = Preferences
iCloudMailFixPrefs_INSTALL_PATH = /Library/PreferenceBundles
iCloudMailFixPrefs_CFLAGS = -fobjc-arc

include $(THEOS_MAKE_PATH)/bundle.mk
