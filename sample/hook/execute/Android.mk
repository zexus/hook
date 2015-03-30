LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := demo_main

LOCAL_SHARED_LIBRARIES := libdemo_hook

LOCAL_SRC_FILES := demo_main.c

include $(BUILD_EXECUTABLE)