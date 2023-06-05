LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

LOCAL_MODULE := ilitek_tddi
LOCAL_SRC_FILES := \
	MP/ilitek_mp.c \
	MP/Android.c	\
	MP/Commom_IlitekMP.c	\
	hid_ic.c	\
	hid_i2c.c	\
	hid_i2c_flash.c		\
    hid_i2c_main.c

# LOCAL_SRC_FILES := \
# 	hid_ic.c	\
# 	hid_i2c.c	\
# 	hid_i2c_flash.c	\
#   hid_i2c_main.c

LOCAL_LDLIBS += -llog
LOCAL_LDFLAGS += -Wl,--no-fatal-warnings -pie -fPIE
LOCAL_CFLAGS += -pie -fPIE -static
include $(BUILD_EXECUTABLE)

