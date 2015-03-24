LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
	demo.c \
	elf_util.c \
	ptrace_util.c

#LOCAL_CFLAGS += -DGL_GLEXT_PROTOTYPES -DEGL_EGLEXT_PROTOTYPES

LOCAL_C_INCLUDES += ../../../include

LOCAL_SHARED_LIBRARIES := \
	libcutils \
	liblog \
	libandroidfw \
	libutils \
	libbinder \
	libui \
	libskia \
	libEGL \
	libGLESv1_CM \
	libgui \
	libtinyalsa

LOCAL_LDLIBS += -llog

LOCAL_MODULE:= hook

include $(BUILD_EXECUTABLE)
