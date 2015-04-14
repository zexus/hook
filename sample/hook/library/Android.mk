LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := libdemo_hook

LOCAL_SRC_FILES := demo_hook.c

LOCAL_LDLIBS += -llog

LOCAL_LDFLAGS += -Wl,--no-warn-shared-textrel -ldl -O0

include $(BUILD_SHARED_LIBRARY)