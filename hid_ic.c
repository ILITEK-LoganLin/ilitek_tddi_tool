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
#include "hidi2c.h"
#include "MP/Android.h"
#include "MP/Common.h"

struct ilitek_ts_data_mp *ilitsmp;
struct ilitek_ic_info chip;
struct ilitek_tp_info tp_info;

#define PROTOCL_VER_NUM		8
static struct ilitek_protocol_info protocol_info[PROTOCL_VER_NUM] = {
	/* length -> fw, protocol, tp, key, panel, core, func, window, cdc, mp_info */
	{PROTOCOL_VER_500, 4, 4, 14, 30, 5, 5, 2, 8, 3, 8},
	{PROTOCOL_VER_510, 4, 3, 14, 30, 5, 5, 3, 8, 3, 8},
	{PROTOCOL_VER_520, 4, 4, 14, 30, 5, 5, 3, 8, 3, 8},
	{PROTOCOL_VER_530, 9, 4, 14, 30, 5, 5, 3, 8, 3, 8},
	{PROTOCOL_VER_540, 9, 4, 14, 30, 5, 5, 3, 8, 15, 8},
	{PROTOCOL_VER_550, 9, 4, 14, 30, 5, 5, 3, 8, 15, 14},
	{PROTOCOL_VER_560, 9, 4, 14, 30, 5, 5, 3, 8, 15, 14},
	{PROTOCOL_VER_570, 9, 4, 14, 30, 5, 5, 3, 8, 15, 14},
};

void ili_ic_disable_report(void)
{
    ilits.wbuf[0] = 0x01;
    ilits.wbuf[1] = 0x24;
    ilits.wbuf[2] = 0x00;
    if (ilits.wrapper(ilits.wbuf, 3, NULL, 0) < 0)
        ILI_ERR("Write disable report cmd failed\n");
}

void ili_ic_set_engineer_mode(void)
{
    ilits.wbuf[0] = 0x01;
    ilits.wbuf[1] = 0x23;
    ilits.wbuf[2] = 0x01;
    if (ilits.wrapper(ilits.wbuf, 3, NULL, 0) < 0)
        ILI_ERR("Write disable report cmd failed\n");
}

int ili_ic_get_core_ver(void)
{
    int ret = 0;
    ilits.wbuf[0] = P5_X_READ_DATA_CTRL;
    ilits.wbuf[1] = P5_X_GET_CORE_VERSION_NEW;

    if (ilits.wrapper(ilits.wbuf, 2, NULL, 0) < 0)
        ILI_ERR("Write core ver cmd failed\n");

    ilits.wbuf[0] = P5_X_GET_CORE_VERSION_NEW;
    if (ilits.wrapper(ilits.wbuf, 1, ilits.rbuf, 5) < 0)
        ILI_ERR("Write core ver (0x%x) failed\n", ilits.wbuf[READ_SHIFT - 1]);
    ilits.chip.core_ver = (ilits.rbuf[READ_SHIFT] << 24) | (ilits.rbuf[READ_SHIFT + 1] << 16) | (ilits.rbuf[READ_SHIFT + 2] << 8) | ilits.rbuf[READ_SHIFT + 3];
    ILI_INFO("Core version = %d.%d.%d.%d\n", ilits.chip.core_ver >> 24, (ilits.chip.core_ver >> 16) & 0xFF
        , (ilits.chip.core_ver >> 8) & 0xFF, ilits.chip.core_ver & 0xFF);

    if (ilits.rbuf[READ_SHIFT - 1] != P5_X_GET_CORE_VERSION_NEW)
    {
        ILI_ERR("Invalid core ver\n");
        ret = -1;
    }

    return ret;
}

int ili_ic_get_fw_ver(bool showinfo)
{
    int ret = 0;
    u8 cmd[2] = {0};

    cmd[0] = P5_X_READ_DATA_CTRL;
    cmd[1] = P5_X_GET_FW_VERSION;

    if (ilits.wrapper(cmd, 2, NULL, 0) < 0)
    {
        ILI_ERR("Write pre cmd failed\n");
        ret = -EINVAL;
        goto out;
    }

    if (ilits.wrapper(&cmd[1], 1, ilits.rbuf, 10) < 0)
    {
        ILI_ERR("Write fw version cmd failed\n");
        ret = -EINVAL;
        goto out;
    }

    if (ilits.rbuf[READ_SHIFT - 1] != P5_X_GET_FW_VERSION)
    {
        ILI_ERR("Invalid firmware ver\n");
        ret = -1;
    }

out:
    if (showinfo) {
        ILI_INFO("Firmware version = %d.%d.%d.%d\n", ilits.rbuf[READ_SHIFT], ilits.rbuf[READ_SHIFT + 1], ilits.rbuf[READ_SHIFT + 2], ilits.rbuf[READ_SHIFT + 3]);
        ILI_INFO("Firmware MP version = %d.%d.%d.%d\n", ilits.rbuf[READ_SHIFT + 4], ilits.rbuf[READ_SHIFT + 5], ilits.rbuf[READ_SHIFT + 6], ilits.rbuf[READ_SHIFT + 7]);
    }
    ilits.chip.fw_ver_buf[3] = ilits.rbuf[READ_SHIFT];
    ilits.chip.fw_ver_buf[2] = ilits.rbuf[READ_SHIFT + 1];
    ilits.chip.fw_ver_buf[1] = ilits.rbuf[READ_SHIFT + 2];
    ilits.chip.fw_ver_buf[0] = ilits.rbuf[READ_SHIFT + 3];
    ilits.chip.fw_ver = ilits.rbuf[READ_SHIFT] << 24 | ilits.rbuf[READ_SHIFT + 1] << 16 | ilits.rbuf[READ_SHIFT + 2] << 8 | ilits.rbuf[READ_SHIFT + 3];
    ilits.chip.fw_mp_ver = ilits.rbuf[READ_SHIFT + 4] << 24 | ilits.rbuf[READ_SHIFT + 5] << 16 | ilits.rbuf[READ_SHIFT + 6] << 8 | ilits.rbuf[READ_SHIFT + 7];
    return ret;
}

int ili_ic_get_protocl_ver(void)
{
    int ret = 0;
    u8 cmd[2] = {0};

    cmd[0] = P5_X_READ_DATA_CTRL;
    cmd[1] = P5_X_GET_PROTOCOL_VERSION;

    if (ilits.wrapper(cmd, sizeof(cmd), NULL, 0) < 0)
    {
        ILI_ERR("Write protocol ver pre cmd failed\n");
        ret = -EINVAL;
        goto out;
    }

    if (ilits.wrapper(&cmd[1], sizeof(u8), ilits.rbuf, 6) < 0)
    {
        ILI_ERR("Read protocol version error\n");
        ret = -EINVAL;
        goto out;
    }

    if (ilits.rbuf[READ_SHIFT - 1] != P5_X_GET_PROTOCOL_VERSION)
    {
        ILI_ERR("Invalid protocol ver\n");
        ret = -1;
        goto out;
    }

out:
    ilits.chip.potocal_ver = ilits.rbuf[READ_SHIFT] << 16 | ilits.rbuf[READ_SHIFT + 1] << 8 | ilits.rbuf[READ_SHIFT + 2];

    ILI_INFO("Protocol version = %d.%d.%d\n", ilits.chip.potocal_ver >> 16, (ilits.chip.potocal_ver >> 8) & 0xFF, ilits.chip.potocal_ver & 0xFF);
    return ret;
}

int ili_ic_init(void)
{
    ILI_DBG("ili_ic_init()\n");

	ilitsmp = (ilitek_ts_data_mp *) malloc(sizeof(struct ilitek_ts_data_mp) * sizeof(u8));
	if (ERR_ALLOC_MEM(ilitsmp)) {
		ILI_ERR("Failed to allocate core_config mem\n");
		return -ENOMEM;
	}


    ilitsmp->protocol = &protocol_info[PROTOCL_VER_NUM - 1];
    ilits.chip = chip;
    ilitsmp->ice_stat = DISABLE;

	return 0;
}

int ili_ic_get_info(void)
{
	int ret = 0;
    u32 pid = 0;

    if (ili_ice_mode_read(TDDI_PID_ADDR, &pid, sizeof(u32)) < 0)
		ILI_ERR("Read pc conter error\n");

	ilits.chip.pid = pid;
	ilits.chip.id = pid >> 16;
	ilits.chip.type = (pid & 0x0000FF00) >> 8;
	ilits.chip.ver = pid & 0xFF;

    if (ili_ice_mode_read(TDDI_OTP_ID_ADDR, &ilits.chip.otp_id, sizeof(u32)) < 0)
		ILI_ERR("Read pc conter error\n");

    if (ili_ice_mode_read(TDDI_ANA_ID_ADDR, &ilits.chip.ana_id, sizeof(u32)) < 0)
		ILI_ERR("Read pc conter error\n");

	ILI_INFO("CHIP: PID = 0x%x, ID = 0x%x, TYPE = 0x%x, VER = 0x%X, OTP = 0x%X, ANA = 0x%X\n",
		ilits.chip.pid,
		ilits.chip.id,
		ilits.chip.type,
		ilits.chip.ver,
		ilits.chip.otp_id,
		ilits.chip.ana_id);
	return ret;
}

int ili_ic_get_tp_info(void)
{
    int ret = 0;
    u8 cmd[2] = {0};

    cmd[0] = P5_X_READ_DATA_CTRL;
	cmd[1] = P5_X_GET_TP_INFORMATION;

    if (ilits.wrapper(cmd, sizeof(cmd), NULL, 0) < 0)
    {
        ILI_ERR("Write protocol ver pre cmd failed\n");
        ret = -EINVAL;
        goto out;
    }

    if (ilits.wrapper(&cmd[1], sizeof(u8), ilits.rbuf, ilitsmp->protocol->tp_info_len) < 0)
	{
		ILI_ERR("Read tp info error\n");
		ret = -EINVAL;
		goto out;
	}

	if (ilits.rbuf[READ_SHIFT - 1] != P5_X_GET_TP_INFORMATION) {
		ILI_ERR("Invalid tp info\n");
		ret = -1;
		goto out;
	}

out:
    tp_info.min_x = ilits.rbuf[READ_SHIFT];
    tp_info.min_y = ilits.rbuf[READ_SHIFT + 1];
    tp_info.max_x = ilits.rbuf[READ_SHIFT + 3] << 8 | ilits.rbuf[READ_SHIFT + 2];
    tp_info.max_y = ilits.rbuf[READ_SHIFT + 5] << 8 | ilits.rbuf[READ_SHIFT + 4];
    tp_info.xch_num = ilits.rbuf[READ_SHIFT + 6];
    tp_info.ych_num = ilits.rbuf[READ_SHIFT + 7];
    tp_info.stx = ilits.rbuf[READ_SHIFT + 10];
    tp_info.srx = ilits.rbuf[READ_SHIFT + 11];
    ilitsmp->tp_info = &tp_info;

	ILI_INFO("TP Info: min_x = %d, min_y = %d, max_x = %d, max_y = %d\n", ilitsmp->tp_info->min_x, ilitsmp->tp_info->min_y, ilitsmp->tp_info->max_x, ilitsmp->tp_info->max_y);
	ILI_INFO("TP Info: xch = %d, ych = %d, stx = %d, srx = %d\n", ilitsmp->tp_info->xch_num, ilitsmp->tp_info->ych_num, ilitsmp->tp_info->stx, ilitsmp->tp_info->srx);
    return ret;
}

int ili_ic_get_panel_info(void)
{
    int ret = 0;
    u8 cmd[2] = {0};

    cmd[0] = P5_X_GET_PANEL_INFORMATION;

    if (ilits.wrapper(cmd, sizeof(u8), ilits.rbuf, ilitsmp->protocol->panel_info_len) < 0)
    {
        ILI_ERR("Read panel info error\n");
        ret = -EINVAL;
    }

    ilitsmp->tp_info->panel_wid = ilits.rbuf[READ_SHIFT + 0] << 8 | ilits.rbuf[READ_SHIFT + 1];
    ilitsmp->tp_info->panel_hei = ilits.rbuf[READ_SHIFT + 2] << 8 | ilits.rbuf[READ_SHIFT + 3];;
	ILI_INFO("Panel info: width = %d, height = %d\n", ilitsmp->tp_info->panel_wid, ilitsmp->tp_info->panel_hei);

    return ret;
}

void ili_ic_get_pc_counter(void)
{
    u32 pc = 0, latch = 0;
    if (ili_ice_mode_read(TDDI_PC_COUNTER_ADDR, &pc, sizeof(u32)) < 0)
		ILI_ERR("Read pc conter error\n");

	if (ili_ice_mode_read(TDDI_PC_LATCH_ADDR, &latch, sizeof(u32)) < 0)
		ILI_ERR("Read pc latch error\n");

    ILI_ERR("Read counter (addr: 0x%x) = 0x%x, latch (addr: 0x%x) = 0x%x\n",
		TDDI_PC_COUNTER_ADDR, pc, TDDI_PC_LATCH_ADDR, latch);
}

void switch_bootloader(void)
{
    // AP to BL CMD
    ilits.wbuf[0] = 0x8E;
    ilits.wrapper(ilits.wbuf, 1, NULL, 0);
    msleep(MODE_CHANGE_DELAY_T);
}

int ili_ic_check_busy(int count, int delay)
{
	u8 cmd[2] = {0};
	u8 busy[4] = {0}, rby = 0;

	cmd[0] = P5_X_READ_DATA_CTRL;
	cmd[1] = P5_X_CDC_BUSY_STATE;

	if (ilitsmp->actual_tp_mode == P5_X_FW_AP_MODE)
		rby = 0x41;
	else if (ilitsmp->actual_tp_mode == P5_X_FW_TEST_MODE)
		rby = 0x51;
	else {
		ILI_ERR("Unknown TP mode (0x%x)\n", ilitsmp->actual_tp_mode);
		return -EINVAL;
	}

	ILI_INFO("read byte = %x, delay = %d\n", rby, delay);

	do {
		if (ilits.wrapper(cmd, sizeof(cmd), NULL, 0) < 0)
			ILI_ERR("Write check busy cmd failed\n");

		if (ilits.wrapper(&cmd[1], sizeof(u8), &busy[0], sizeof(u8)) < 0)
			ILI_ERR("Read check busy failed\n");
		ILI_DBG("busy = 0x%x\n", busy[READ_OFFSET]);

		if (busy[READ_OFFSET] == rby) {
			ILI_INFO("Check busy free\n");
			return 0;
		}
		msleep(delay);
	} while (--count > 0);

	ILI_ERR("Check busy (0x%x) timeout !\n", busy[READ_OFFSET]);
	ili_ic_get_pc_counter();

	return -1;
}

int ili_move_mp_code_flash(void)
{
	int ret = 0;
	u8 cmd[2] = {0};

	cmd[0] = P5_X_NEW_CONTROL_FORMAT;
	cmd[1] = P5_X_FW_TEST_MODE;
	ret = ilits.wrapper(cmd, 2, NULL, 0);
	if (ret < 0)
		goto out;

    /* Check if ic is ready switching test mode from demo mode */
	ilitsmp->actual_tp_mode = P5_X_FW_AP_MODE;
	ret = ili_ic_check_busy(20, 50); /* Set busy as 0x41 */
	if (ret < 0)
		goto out;

	ili_ice_mode_write(0x4005C, 0x36A9, 2);
	ili_ic_whole_reset(OFF);
    msleep(100);

    ilitsmp->actual_tp_mode = P5_X_FW_TEST_MODE; /* set busy as 0x51 */

	ret = ili_ic_check_busy(20, 50);
	if (ret < 0)
		ILI_ERR("Check cdc timeout failed after moved mp code\n");

out:
    return ret;
}

int ili_hid_switch_tp_mode(u8 mode)
{
    int ret = 0;

    if (mode == P5_X_FW_AP_MODE) {
        ili_ice_mode_write(0x4005C, 0x0, 2);
        ili_ic_whole_reset(OFF);
        msleep(100);

    } else if (P5_X_FW_TEST_MODE){
        ret = ili_move_mp_code_flash();
    }
    return ret;
}

int ili_mp_lcm_ctrl(u8 lcm_on)
{
    int ret = 0;
    u8 cmd[4] = {0x0F,0x02,0x00,0x01};

    cmd[3] = (lcm_on == ON) ? 0x01 : 0x02;
    if (ilits.wrapper(cmd, sizeof(cmd), NULL, 0) < 0)
    {
        ILI_ERR("write lcm ctrl cmd error\n");
        ret = RET_FAIL_NO;
    }

    return ret;
}

void ili_ic_free(void)
{
	ILI_INFO("Remove config memebers\n");
	ipio_vfree((void **)&ilitsmp);
}