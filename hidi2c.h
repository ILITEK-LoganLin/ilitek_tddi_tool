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
#ifndef __HIDI2C_H__
#define __HIDI2C_H__

#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <poll.h>

#include <linux/hidraw.h>
#include <sys/ioctl.h>

#define HID_DAEMON_VERSION "2.0.5.0"

#define CPLUS_COMPILER ENABLE

#define HID_RAW_NODE "/dev/hidraw0"
#define RET_FAIL_NO -1
#define DEF_FW_FILP_PATH "/sdcard/ILITEK_FW"
#define DEF_INI_FILP_PATH "/sdcard/mp.ini"
#define DEF_MP_FILP_PATH "/sdcard/"
#define DEF_MP_LCM_ON_PATH "/sdcard/ilitek_mp_lcm_on_log/"
#define DEF_MP_LCM_OFF_PATH "/sdcard/ilitek_mp_lcm_off_log/"
#define HEX_CHK_KEY1 "flashbl"
#define HEX_CHK_KEY2 "IlitekBL"

#define RW_SYNC 0
#define R_ONLY 1
#define W_ONLY 2

#define ENABLE 1
#define DISABLE 0
#define ON 1
#define OFF 0
#define K (1024)
#define M (K * K)
#define READ_SHIFT 4
#define READ_OFFSET 3
#define MP_CDC_READ_OFFSET 1

#define ILITEK_VENDOR_ID 0x222A

#define P5_X_FW_AP_MODE 0x00
#define P5_X_FW_TEST_MODE 0x01
#define P5_X_FW_DEBUG_MODE 0x02

#define P5_X_READ_DATA_CTRL 0xF6
#define P5_X_GET_TP_INFORMATION 0x20
#define P5_X_GET_FW_VERSION 0x21
#define P5_X_GET_PROTOCOL_VERSION 0x22
#define P5_X_GET_CORE_VERSION 0x23
#define P5_X_GET_CORE_VERSION_NEW 0x24
#define P5_X_GET_KEY_INFORMATION 0x27
#define P5_X_GET_PANEL_INFORMATION 0x29
#define P5_X_GET_PEN_INFO 0x27
#define P5_X_GET_ALL_INFORMATION 0x2F

#define POSITION_PEN_TYPE_ON 0x00
#define POSITION_PEN_TYPE_OFF 0x03

#define FW_BLOCK_INFO_NUM 17

#define RET_PASS 0
#define RET_FAIL 1

#define UPDATE_PASS 0
#define UPDATE_FAIL -1
#define TIMEOUT_SECTOR 25
#define TIMEOUT_PAGE 3500
#define TIMEOUT_PROGRAM 10
#define BOOTLOADER_BLOCK_END 0x4000

#define ILI9882_CHIP 0x9882
#define TDDI_PID_ADDR 0x4009C

#define TDDI_CHIP_RESET_ADDR 0x40050
#define TDDI_WHOLE_CHIP_RST_WITH_FLASH_KEY 0x00019878
#define TDDI_WHOLE_CHIP_RST_WITHOUT_FLASH_KEY 0xA0019878

#define MAX_HEX_FILE_SIZE (256 * K)
#define INFO_HEX_ST_ADDR 0x4F
#define INFO_MP_HEX_ADDR 0x1F

#define CMD_DELIN "="

#define CMD_DELAY_T 1
#define POLLING_BUSY_DELAY_T 4
#define MODE_CHANGE_DELAY_T 100
#define RST_DELAY_T 270
#define WDT_DELAY_T 3000
#define WAIT_BL_FLASH_DONE_T 20
#define RETRY_UPGRADE_T 200
#define FW_UPGRADE_RETRY 3

#define AP_INT_TIMEOUT 600  /*600ms*/
#define MP_INT_TIMEOUT 5000 /*5000ms*/

/* Flash */
#define FLASH_BASED_ADDR 0x41000
#define FLASH0_ADDR (FLASH_BASED_ADDR + 0x0)
#define FLASH1_ADDR (FLASH_BASED_ADDR + 0x4)
#define FLASH2_ADDR (FLASH_BASED_ADDR + 0x8)
#define FLASH3_ADDR (FLASH_BASED_ADDR + 0xC)
#define FLASH4_ADDR (FLASH_BASED_ADDR + 0x10)

#define FLASH0_CS FLASH0_ADDR
#define FLASH1_KEY FLASH1_ADDR
#define FLASH1_DUAL_MODE (FLASH_BASED_ADDR + 0x3)
#define FLASH2_FALSH_ID FLASH2_ADDR

#define TDDI_PC_COUNTER_ADDR 0x44008
#define TDDI_PC_LATCH_ADDR 0x51010

typedef unsigned char u8;
typedef unsigned short int u16;
typedef unsigned int u32;
typedef unsigned long u64;
typedef signed char s8;
typedef short int s16;
typedef signed int s32;

extern bool debug_log_en;
extern bool log_en;
#define ILI_INFO(fmt, arg...)                                    \
    do                                                           \
    {                                                            \
        if (log_en)                                              \
            printf("(%s, %d): " fmt, __func__, __LINE__, ##arg); \
    } while (0)
#define ILI_DBG(fmt, arg...)                                     \
    do                                                           \
    {                                                            \
        if (debug_log_en)                                        \
            printf("(%s, %d): " fmt, __func__, __LINE__, ##arg); \
    } while (0)
#define ILI_ERR(fmt, arg...)                                     \
    do                                                           \
    {                                                            \
        if (log_en)                                              \
            printf("(%s, %d): " fmt, __func__, __LINE__, ##arg); \
    } while (0)

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#define msleep(n) usleep(n * 1000)

enum LCM
{
    LCM_OFF = 0,
    LCM_ON,
};

enum TP_FW_BLOCK_NUM
{
    AP = 1,
    DATA = 2,
    TUNING = 3,
    GESTURE = 4,
    MP = 5,
    DDI = 6,
    TAG = 7,
    PARA_BACKUP = 8,
    BOOTLOADER = 9,
    PEN = 10,
    RESERVE_BLOCK5 = 11,
    RESERVE_BLOCK6 = 12,
    RESERVE_BLOCK7 = 13,
    RESERVE_BLOCK8 = 14,
    RESERVE_BLOCK9 = 15,
    RESERVE_BLOCK10 = 16,
};

enum TP_ERR_CODE
{
    EMP_CMD = 100,
    EMP_PROTOCOL,
    EMP_FILE,
    EMP_INI,
    EMP_TIMING_INFO,
    EMP_INVAL,
    EMP_PARSE,
    EMP_NOMEM,
    EMP_GET_CDC,
    EMP_INT,
    EMP_CHECK_BUY,
    EMP_MODE,
    EMP_FW_PROC,
    EMP_FORMUL_NULL,
    EMP_PARA_NULL,
    EFW_CONVERT_FILE,
    EFW_ICE_MODE,
    EFW_CRC,
    EFW_REST,
    EFW_ERASE,
    EFW_PROGRAM,
    EFW_INTERFACE,
    EFW_HEXSIGH,
};

enum TP_IC_TYPE
{
    ILI_A = 0x0A,
    ILI_B,
    ILI_C,
    ILI_D,
    ILI_E,
    ILI_F,
    ILI_G,
    ILI_H,
    ILI_I,
    ILI_J,
    ILI_K,
    ILI_L,
    ILI_M,
    ILI_N,
    ILI_O,
    ILI_P,
    ILI_Q,
    ILI_R,
    ILI_S,
    ILI_T,
    ILI_U,
    ILI_V,
    ILI_W,
    ILI_X,
    ILI_Y,
    ILI_Z,
};

enum TP_FW_BLOCK_TAG
{
    BLOCK_TAG_AF = 0xAF,
    BLOCK_TAG_B0 = 0xB0,
    BLOCK_TAG_SIGN = 0xEE,
    BLOCK_TAG_BLKEY = 0xDE,
};
enum WR_TP_REG
{
    READ,
    WRITE,
};

struct report_info_block
{
    u8 nReportByPixel : 1;
    u8 nIsHostDownload : 1;
    u8 nIsSPIICE : 1;
    u8 nIsSPISLAVE : 1;
    u8 nIsI2C : 1;
    u8 nReserved00 : 3;
    u8 nReportResolutionMode : 3;
    u8 nCustomerType : 5;
    u8 nReserved02 : 8;
    u8 nReserved03 : 8;
};

struct firmware
{
    size_t size;
    const u8 *data;

    /* firmware loader private fields */
    void *priv;
};

struct ilitek_ic_info
{
    u8 type;
    u8 ver;
    u16 id;
    u32 pid;
    u32 pid_addr;
    u32 wdt_addr;
    u32 pc_counter_addr;
    u32 pc_latch_addr;
    u32 reset_addr;
    u32 otp_addr;
    u32 ana_addr;
    u32 otp_id;
    u32 ana_id;
    u32 fw_ver;
    u8 fw_ver_buf[4];
    u32 fw_mp_ver;
    u32 driver_ver[4];
    u32 core_ver;
    u32 max_count;
    u32 reset_key;
    u16 wtd_key;
    int no_bk_shift;
    u32 fw_pc;
    u32 fw_latch;
    u32 bl_ver;
    u32 potocal_ver;
};

struct pen_info_block
{
    u8 nPxRaw;
    u8 nPyRaw;
    u8 nPxVa;
    u8 nPyVa;
    u8 nPenX_MP;
    u8 nReserved01;
    u8 nReserved02;
    u8 nReserved03;
};

struct ilitek_ts_data
{
    struct ilitek_ic_info chip;
    struct firmware tp_fw;
    struct report_info_block rib;

    u8 PenType;
    struct pen_info_block pen_info_block;

    int fd_hidraw;
    u8 fw_path[512];
    u8 wbuf[256];
    u8 rbuf[8192];
    u8 save_path[128];
    u8 ini_path[128];
    u8 data[32];
    char hidnode[64];
    char hidtestnode[64];

    bool isSupportFlash;
    bool flash_bl_key_en;
    bool flash_bl_en;

    u16 flash_mid;
    u16 flash_devid;
    u8 current_report_rate_mode;
    u8 fw_info[75];
    u8 fw_mp_ver[4];
    int program_page;
    int flash_sector;
    int fw_update_stat;
    int supportFlashIndex;
    const char *flashName;

    char *md_fw_filp_path;

    /* current firmware mode in driver */
    u16 actual_tp_mode;
    int ice_stat;

    int (*wrapper)(u8 *wdata, u32 wlen, u8 *rdata, u32 rlen);
};

static inline void *ipio_memcpy(void *dest, const void *src, int n, int dest_size)
{
    if (n > dest_size)
        n = dest_size;

    return memcpy(dest, src, n);
}

static inline void ipio_free(void **mem)
{
    if (*mem != NULL)
    {
        free(*mem);
        *mem = NULL;
    }
}

extern struct ilitek_ts_data ilits;
extern struct hidraw_report_descriptor rpt_desc;
extern struct hidraw_devinfo info;
extern struct ilitek_ic_info chip;

extern struct ilitek_ts_data_mp *ilitsmp;

extern int open_hid_node(void);
extern int open_hidraw_device(void);
extern void close_hid_node(void);
extern void init_hid(void);
extern void check_hidraw_info(void);
extern void ili_dump_data(void *data, int type, int len, int row_len, const char *name);
extern void ili_read_flash_info(void);
extern void ili_ic_whole_reset(bool withflash);
extern int ili_i2c_wrapper(u8 *txbuf, u32 wlen, u8 *rxbuf, u32 rlen);
extern int ili_ice_mode_write(u32 addr, u32 data, int len);
extern int ili_ice_mode_read(u32 addr, u32 *data, int len);
extern int do_fw_upgrade(void);
extern int open_hex(char *file_path);
extern bool is_in_bootloader_mode(void);
extern int ili_fw_read_hw_crc(u32 start, u32 write_len, u32 *flash_crc);
extern int ili_ic_get_core_ver(void);
extern int ili_ic_get_fw_ver(bool showinfo);
extern int ili_ic_get_protocl_ver(void);
extern int ili_ic_get_info(void);
extern void ili_ic_disable_report(void);
extern void ili_ic_set_engineer_mode(void);
extern int ilitek_tddi_flash_fw_crc_check(void);
extern int get_info(void);
extern void ili_ic_get_pc_counter(void);
extern int do_fw_upgrade_test(void);
extern int ili_mp_test(u8 *ini_path, u8 *save_path);
extern void ili_ic_check_protocol_ver(u32 pver);
extern int ili_ic_get_tp_info(void);
extern int ili_ic_get_pen_info(void);
extern int ili_ic_get_panel_info(void);
extern int ili_hid_switch_tp_mode(u8 mode);
extern void switch_bootloader(void);
extern int check_fw_crc(char *file_path);
extern int ili_mp_lcm_ctrl(u8 lcm_on);
extern int ili_mp_test_main(bool lcm_on);
extern int ili_ic_get_all_info(void);
#endif