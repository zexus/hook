LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := writedata

#LOCAL_SHARED_LIBRARIES := libdemo_hook

LOCAL_SRC_FILES := writedata.c

include $(BUILD_EXECUTABLE)