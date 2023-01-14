TARGET := iphone:clang:latest:13.0
INSTALL_TARGET_PROCESSES = Messenger


include $(THEOS)/makefiles/common.mk

TWEAK_NAME = GroupPatcher

GroupPatcher_CODESIGN_FLAGS = -Sent.plist
GroupPatcher_FILES = GroupPatcher.m 
GroupPatcher_FILES += Fishhook/fishhook.c
GroupPatcher_FILES += EntitlementsForImage/EntitlementsForImage.m
GroupPatcher_CFLAGS = -fobjc-arc
GroupPatcher_FRAMEWORKS = Security
include $(THEOS_MAKE_PATH)/tweak.mk
