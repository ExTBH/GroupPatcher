export ARCHS = arm64
TARGET := iphone:clang:14.5:10.0
INSTALL_TARGET_PROCESSES = Messenger


include $(THEOS)/makefiles/common.mk

TWEAK_NAME = GroupPatcher

GroupPatcher_FILES = GroupPatcher.m 
# GroupPatcher_FILES += Fishhook/fishhook.c
# GroupPatcher_FILES += EntitlementsForImage/EntitlementsForImage.m
GroupPatcher_CFLAGS = -fobjc-arc
include $(THEOS_MAKE_PATH)/tweak.mk
