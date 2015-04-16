LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := inject

LOCAL_SRC_FILES :=  inject.c \
                    elf_utils.c \
                    ptrace_utils.c

LOCAL_CFLAGS += -pie -fPIE

LOCAL_LDFLAGS += -pie -fPIE

LOCAL_LDLIBS += -L$(SYSROOT)/usr/lib -llog -ldl

#LOCAL_FORCE_STATIC_EXECUTABLE := true

include $(BUILD_EXECUTABLE)
