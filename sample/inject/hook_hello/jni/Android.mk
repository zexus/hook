LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_LDLIBS += -L$(SYSROOT)/usr/lib -llog -lEGL
#LOCAL_ARM_MODE := arm
LOCAL_MODULE    := hook
LOCAL_SRC_FILES := hook.c
include $(BUILD_SHARED_LIBRARY)