#!/bin/sh 
DAEMON=ilitek_tddi

# rm $DAEMON"_x86_x64"
# rm $DAEMON"_arm"
rm $DAEMON

# gcc -static \
# 	   	MP/ilitek_mp.c \
# 		MP/Android.c	\
# 		MP/Commom_IlitekMP.c	\
# 		hid_ic.c	\
# 		hid_i2c.c	\
# 		hid_i2c_flash.c		\
# 		hid_i2c_main.c		\
# 	-o $DAEMON"_x86_x64"  -lm -DCONFIG_ILITEK_USE_LIBUSB

# Build for arm
# aarch64-linux-gnu-gcc \
# 	-static \
# 		MP/ilitek_mp.c \
# 		MP/Android.c	\
# 		MP/Commom_IlitekMP.c	\
# 		hid_ic.c	\
# 		hid_i2c.c	\
# 		hid_i2c_flash.c		\
# 		hid_i2c_main.c		\
# 	-o $DAEMON"_arm"  -lm -DCONFIG_ILITEK_USE_LIBUSB

	
aarch64-linux-gnu-gcc \
	-static \
		MP/ilitek_mp.c \
		MP/Android.c	\
		MP/Commom_IlitekMP.c	\
		hid_ic.c	\
		hid_i2c.c	\
		hid_i2c_flash.c		\
		hid_i2c_main.c		\
	-o $DAEMON  -lm -DCONFIG_ILITEK_USE_LIBUSB