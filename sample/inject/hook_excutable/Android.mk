LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
	main.c

LOCAL_CFLAGS += -pie -fPIE

LOCAL_LDFLAGS += -pie -fPIE

LOCAL_LDLIBS += -L$(SYSROOT)/usr/lib -llog -ldl -linject

LOCAL_MODULE := main

include $(BUILD_EXECUTABLE)
