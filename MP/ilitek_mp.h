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

#ifndef __ILI9881_H
#define __ILI9881_H

#include "Common.h"

#define ILITEK_DEBUG	0

enum TP_ICE_MCU_MODE {
	MUC_STOP = 0,
	MUC_ON = 1,
};

/* Define Handshake FLAG */
#define HANDSHAKE_IRQ_ALL_ON        1
#define HANDSHAKE_IRQ_ALL_OFF       2
#define HANDSHAKE_IRQ_OTHER         3


/* Firmware upgrade */
#define CORE_VER_1410				0x01040100
#define CORE_VER_1420				0x01040200
#define CORE_VER_1430				0x01040300
#define CORE_VER_1600				0x01060000

/* Protocol */
#define PROTOCOL_VER_500				    0x050000
#define PROTOCOL_VER_510				    0x050100
#define PROTOCOL_VER_520				    0x050200
#define PROTOCOL_VER_530				    0x050300
#define PROTOCOL_VER_540				    0x050400
#define PROTOCOL_VER_550				    0x050500
#define PROTOCOL_VER_560				    0x050600
#define PROTOCOL_VER_570				    0x050700
#define P5_X_READ_DATA_CTRL				    0xF6
#define P5_X_GET_TP_INFORMATION			    0x20
#define P5_X_GET_KEY_INFORMATION		    0x27
#define P5_X_GET_PANEL_INFORMATION		    0x29
#define P5_X_GET_FW_VERSION				    0x21
#define P5_X_GET_PROTOCOL_VERSION		    0x22
#define P5_X_GET_CORE_VERSION			    0x23
#define P5_X_GET_CORE_VERSION_NEW		    0x24
#define P5_X_MODE_CONTROL				    0xF0
#define P5_X_NEW_CONTROL_FORMAT				0xF2
#define P5_X_SET_CDC_INIT				    0xF1
#define P5_X_GET_CDC_DATA				    0xF2
#define P5_X_CDC_BUSY_STATE				    0xF3
#define P5_X_MP_TEST_MODE_INFO			    0xFE
#define P5_X_I2C_UART					    0x40
#define CMD_GET_FLASH_DATA				    0x41
#define CMD_CTRL_INT_ACTION				    0x1B
#define P5_X_FW_UNKNOWN_MODE			    0xFF
#define P5_X_FW_AP_MODE					    0x00
#define P5_X_FW_TEST_MODE				    0x01
#define P5_X_FW_DEBUG_MODE				    0x02
#define P5_X_FW_GESTURE_MODE			    0x0F
#define P5_X_FW_DELTA_DATA_MODE			    0x03
#define P5_X_FW_RAW_DATA_MODE			    0x08
#define P5_X_DEMO_PACKET_ID				    0x5A
#define P5_X_DEBUG_PACKET_ID			    0xA7
#define P5_X_TEST_PACKET_ID				    0xF2
#define P5_X_GESTURE_PACKET_ID			    0xAA
#define P5_X_GESTURE_FAIL_ID			    0xAE
#define P5_X_I2CUART_PACKET_ID			    0x7A
#define P5_X_SLAVE_MODE_CMD_ID			    0x5F
#define P5_X_INFO_HEADER_PACKET_ID		    0xB7
#define P5_X_DEMO_DEBUG_INFO_PACKET_ID		0x5C
#define P5_X_EDGE_PLAM_CTRL_1				0x01
#define P5_X_EDGE_PLAM_CTRL_2				0x12
#define P5_X_GET_PEN_INFO		            0x27
#define P5_X_GET_ALL_INFORMATION			0x2F
#define SPI_WRITE					        0x82
#define SPI_READ					        0x83
#define SPI_ACK						        0xA3
#define TDDI_WDT_ON					        0xA5
#define TDDI_WDT_OFF					    0x5A

/* Chips */
#define ILI9883_CHIP						0x9883
#define ILI9882_CHIP					    0x9882
#define ILI9881_CHIP					    0x9881
#define ILI7807_CHIP					    0x7807
#define ILI9881N_AA					        0x98811700
#define ILI9881O_AA					        0x98811800

#define TDDI_OTP_ID_ADDR				    0x400A0
#define TDDI_ANA_ID_ADDR				    0x400A4
#define TDDI_PC_COUNTER_ADDR			    0x44008
#define TDDI_PC_LATCH_ADDR				    0x51010
#define TDDI_WDT_ADDR					    0x5100C
#define TDDI_WDT_ACTIVE_ADDR			    0x51018
#define TDDI_CHIP_RESET_ADDR			    0x40050
#define RAWDATA_NO_BK_SHIFT				    8192

/* Driver version */
#define DRIVER_VERSION			"3.0.1.0.200122"

/* A interface currently supported by driver */
#define I2C_INTERFACE		    1
#define SPI_INTERFACE		    2
#define INTERFACE			    SPI_INTERFACE

 /* define the width and heigth of a screen. */
#define TOUCH_SCREEN_X_MIN			0
#define TOUCH_SCREEN_Y_MIN			0
#define TOUCH_SCREEN_X_MAX			720
#define TOUCH_SCREEN_Y_MAX			1440
#define MAX_TOUCH_NUM				10

#define TDDI_I2C_ADDR				0x41
#define TDDI_DEV_ID				    "ILITEK_TDDI"

/* Macros */
#define CHECK_EQUAL(X, Y)				((X == Y) ? 0 : -1)
#define ERR_ALLOC_MEM(X)				((X == NULL) ? 1 : 0)
#ifdef BIT
#undef BIT
#endif
#define BIT(x)	(1 << (x))

#define K			(1024)
#define M			(K * K)
#define ENABLE			1
#define START			1
#define ON			1
#define ILI_WRITE		1
#define ILI_READ		0
#define DISABLE			0
#define END			0
#define OFF			0
#define NONE			-1
#define DO_SPI_RECOVER		-2
#define MP_ITEM_PASS		0
#define MP_ITEM_FAIL		1
#define MP_ITEM_NA			2

#define MP_DATA_PASS			0
#define MP_DATA_FAIL			-1
#define SRAM_OUTPUT_SIZE 		512

/* System Error Define */
#define GFP_KERNEL		0
#define EINVAL			22
#define ENOMEM			12
#define ENOTTY          25

/* Debug messages */
#define DEBUG_NONE	0
#define DEBUG_ALL	1
#define DEBUG_OUTPUT	DEBUG_ALL

struct ilitek_protocol_info {
	u32 ver;
	int fw_ver_len;
	int pro_ver_len;
	int tp_info_len;
	int key_info_len;
	int panel_info_len;
	int core_ver_len;
	int func_ctrl_len;
	int window_len;
	int cdc_len;
	int mp_info_len;
};

struct ilitek_tp_info{

    u16 max_x;
	u16 max_y;
	u16 min_x;
	u16 min_y;
	u8 xch_num;
	u8 ych_num;
	u16 panel_wid;
	u16 panel_hei;
	u8 stx;
	u8 srx;
};

struct ilitek_sram {
	char *csv_sram;
	int ret_sram;
};
struct ilitek_ts_data_mp {

    /* current firmware mode in driver */
    u16 actual_tp_mode;
    int ice_stat;
	int csv_fp;

	struct ilitek_tp_info *tp_info;
    struct ilitek_protocol_info *protocol;

	u8 u8CsvPath[128];
	u8 u8CsvFileName[48];
};

static inline void ipio_kfree(void **mem){
	if (*mem != NULL) {
		free(*mem);
		*mem = NULL;
	}
}

static inline void ipio_vfree(void **mem) {
	if (*mem != NULL) {
		free(*mem);
		*mem = NULL;
	}
}

static inline int ipio_strcmp(const char *s1, const char *s2){
	return (strlen(s1) != strlen(s2)) ? -1 : strncmp(s1, s2, strlen(s1));
}

static inline int ili_str2hex(char *str) {
	int strlen, result, intermed, intermedtop;
	char *s = str;

	while (*s != 0x0) {
		s++;
	}

	strlen = (int)(s - str);
	s = str;
	if (*s != 0x30) {
		return -1;
	}

	s++;

	if (*s != 0x78 && *s != 0x58) {
		return -1;
	}
	s++;

	strlen = strlen - 3;
	result = 0;
	while (*s != 0x0) {
		intermed = *s & 0x0f;
		intermedtop = *s & 0xf0;
		if (intermedtop == 0x60 || intermedtop == 0x40) {
			intermed += 0x09;
		}
		intermed = intermed << (strlen << 2);
		result = result | intermed;
		strlen -= 1;
		s++;
	}
	return result;
}

static inline int ili_katoi(char *str) {
	int result = 0;
	unsigned int digit;
	int sign;

	if (*str == '-') {
		sign = 1;
		str += 1;
	} else {
		sign = 0;
		if (*str == '+') {
			str += 1;
		}
	}

	for (;; str += 1) {
		digit = *str - '0';
		if (digit > 9)
			break;
		result = (10 * result) + digit;
	}

	if (sign) {
		return -result;
	}
	return result;
}

#define kcalloc(ptr, size, arg... )	calloc(ptr, size);
#define vmalloc(size, arg... ) malloc(size);
#define kmalloc(size, arg... ) malloc(size);
#define kstrtol(pToken, base, s_to_long) strtol(pToken, s_to_long, base);

/* Touch IC status */
extern int ili_switch_tp_mode(u8 mode);
extern int ili_ic_check_support(u32 pid, u16 id);
extern int ili_ic_tp_hw_reset(void);

/* Touch IC information */
extern int ili_ic_get_core_ver(void);
extern int ili_ic_get_tp_info(void);
extern int ili_ic_get_panel_info(void);
extern int ili_ic_get_protocol_ver(void);
extern int ili_ic_get_fw_ver(bool showinfo);
extern int ili_ic_get_driver_ver(void);
extern int ili_ic_get_info(void);
extern int ili_ic_init(void);
extern void ili_ic_free(void);

/* Prototypes for tddi mp test */
extern void ili_mp_init_item(void);
extern void ili_mp_test_free(void);
extern int ili_mp_ini_parser(const char *path);
extern void ili_mp_copy_result(char *buf, size_t size);
extern void show_vivo_mp_result(int mpret);
extern void show_commom_mp_result(void);
extern int ili_ic_check_busy(int count, int delay);
extern int ili_hid_switch_tp_mode(u8 mode);

#endif /* __ILI9881_H */
