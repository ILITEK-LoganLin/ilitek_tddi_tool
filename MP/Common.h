/*
 * Copyright (c) 2023 ILI Technology Corp.
 * Copyright (c) 2023 Logan Lin <logan_lin@ilitek.com>
 *
 * This file is part of ILITEK Linux TDDI HID Tool
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *   http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __COMMON_H
#define __COMMON_H

#include <stdint.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <linux/ioctl.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/types.h>
#include <math.h>
#include <memory.h>
#include <ctype.h>
#include <stdbool.h>

#include "../hidi2c.h"

/* Define MP Error Code */
#define MP_TEST_NONE				            0x02
#define MP_TEST_PASS				            0x00
#define MP_TEST_FAIL				            0x01
#define MP_LOAD_MP_INI_FAIL			            0x03
#define MP_CALC_TIMING_FAIL			            0x04
#define MP_GET_CORE_VERSION_FAIL	            0x05
#define MP_IOCTL_CONTROL_FAIL		            0x06
#define MP_SWITCH_MODE_FAIL			            0x07
#define MP_ICE_MODE_ENABLE_FAIL		            0x08
#define MP_GET_PROTOCOL_VERSION_FAIL            0x09
#define MP_OPEN_CONTROLLER_FAIL		            0x10
#define MP_ALLOCATE_MEM_FAIL		            0x11
#define MP_HW_RESET_FAIL			            0x12
#define MP_GET_CHIP_ID_FAIL			            0x13
#define MP_GET_TP_INFO_FAIL 		            0x14
#define MP_ICE_MODE_DISABLE_FAIL                0x15
#define MP_SORT_INI_FAIL                        0x16
#define MP_PROTOCOL_VERSION_INVALID_FAIL        0x17
#define MP_TP_INFO_INVALID_FAIL                 0x18
#define MP_GET_FW_VERSION_FAIL                  0x19
#define MP_GET_PANEL_INFO_FAIL                  0x1A
#define MP_GET_DRIVER_VERSION_FAIL	            0x1B
#define MP_GET_PEN_INFO_FAIL                    0x1C

#define R_BUFF_SIZE 6 * K

#define msleep(n) usleep(n * 1000)


struct _JNI_DATA {
	// declare controller data
	struct IO_CONTROL_DATA {
		int8_t *sName;
		u8 u8NameSize;
		int32_t FileNode;
	} Control;
	struct MP_INFO_DATA{
		int csv_fp;
		u8 u8CsvPath[128];
		u8 u8CsvFileName[48];
	} MP;
	struct I2C_CONTROL_DATA
	{
		u8 I2cAddress;
		u16 u16WriteLen;
		u16 u16ReadLen;
		u16 u16Delay;
		u8 handshake_flag;
		int (*I2c_Transfer)(void);
	} I2c;

    struct TP_INFO_DATA
    {
        u8 u16IceModeFlag;
        u32 driverVer;
    } TP;
};

extern uint8_t u8I2cWriteData[128];
extern uint8_t u8I2cReadData[4096];
extern struct _JNI_DATA Jni;

/* Commom */
#define COMMOM_MP_LCM_ON_PATH		"/sdcard/ilitek_mp_lcm_on_log/"
#define COMMOM_MP_LCM_OFF_PATH		"/sdcard/ilitek_mp_lcm_off_log/"
#define COMMOM_MPINI_PATH			"/sdcard/mp.ini"

#define CSV_TEMP					"mpTemp"
#define DIR_EXIST					-1

#endif /* __COMMON_H */
