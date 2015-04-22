LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_LDLIBS += -L$(SYSROOT)/usr/lib -llog -lEGL -ldl
#LOCAL_ARM_MODE := arm
LOCAL_MODULE    := libhook
LOCAL_SRC_FILES := hook.c
include $(BUILD_SHARED_LIBRARY)
