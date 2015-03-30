LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := libdemo_hook

LOCAL_SRC_FILES := demo_hook.c

include $(BUILD_SHARED_LIBRARY)