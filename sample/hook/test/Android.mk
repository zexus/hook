LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := libhook

LOCAL_LDFLAGS := -ldemo_hook -llog

LOCAL_LDLIBS := -ldemo_hook -llog

LOCAL_SRC_FILES := hook.c

include $(BUILD_SHARED_LIBRARY)
