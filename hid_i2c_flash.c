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
#include "hid_i2c_flash.h"

static u8 *pfw;

u32 get_file_size(char *filename)
{
    u32 size;
    FILE *file = fopen(filename, "r");

    fseek(file, 0, SEEK_END);
    size = ftell(file);
    fclose(file);
    return size;
}

static struct touch_fw_data
{
    u8 block_number;
    u32 start_addr;
    u32 end_addr;
    u32 new_fw_cb;
    int delay_after_upgrade;
    bool isCRC;
    bool isboot;
    bool is80k;
    int hex_tag;
} tfd;

static struct flash_block_info
{
    const char *name;
    u32 start;
    u32 end;
    u32 len;
    u32 mem_start;
    u32 fix_mem_start;
    u8 mode;
} fbi[FW_BLOCK_INFO_NUM];

static u32 HexToDec(u8 *phex, u32 len)
{
    u32 ret = 0, temp = 0, i;
    s32 shift = (len - 1) * 4;

    for (i = 0; i < len; shift -= 4, i++)
    {
        if ((phex[i] >= '0') && (phex[i] <= '9'))
            temp = phex[i] - '0';
        else if ((phex[i] >= 'a') && (phex[i] <= 'f'))
            temp = (phex[i] - 'a') + 10;
        else if ((phex[i] >= 'A') && (phex[i] <= 'F'))
            temp = (phex[i] - 'A') + 10;

        ret |= (temp << shift);
    }
    return ret;
}

u8 ili_calc_packet_checksum(u8 *packet, int len)
{
    int i;
    s32 sum = 0;

    for (i = 0; i < len; i++)
        sum += packet[i];

    return (u8)((-sum) & 0xFF);
}

static int CalculateCRC32(u32 start_addr, u32 len, u8 *pfw)
{
    u32 i = 0, j = 0;
    int crc_poly = 0x04C11DB7;
    int tmp_crc = 0xFFFFFFFF;

    for (i = start_addr; i < start_addr + len; i++)
    {
        tmp_crc ^= (pfw[i] << 24);

        for (j = 0; j < 8; j++)
        {
            if ((tmp_crc & 0x80000000) != 0)
                tmp_crc = tmp_crc << 1 ^ crc_poly;
            else
                tmp_crc = tmp_crc << 1;
        }
    }
    return tmp_crc;
}

static int ilitek_fw_calc_file_crc(u8 *pfw)
{
    int i, block_num = 0;
    u32 ex_addr, data_crc, file_crc;

    for (i = 0; i < FW_BLOCK_INFO_NUM; i++)
    {
        if (fbi[i].len >= MAX_HEX_FILE_SIZE)
        {
            ILI_ERR("Content of fw file is invalid. (fbi[%d].len=0x%x)\n",
                    i, fbi[i].len);
            return -1;
        }

        if (fbi[i].end <= 4)
            continue;
        block_num++;
        ex_addr = fbi[i].end;
        data_crc = CalculateCRC32(fbi[i].start, fbi[i].len - 4, pfw);
        file_crc = pfw[ex_addr - 3] << 24 | pfw[ex_addr - 2] << 16 | pfw[ex_addr - 1] << 8 | pfw[ex_addr];
        ILI_DBG("data crc = %x, file crc = %x\n", data_crc, file_crc);
        if (data_crc != file_crc)
        {
            ILI_ERR("Content of fw file is broken. (%d, %x, %x)\n",
                    i, data_crc, file_crc);
            return -1;
        }
    }

    if (fbi[MP].end <= 4 * K || fbi[AP].end <= 4 * K || (block_num == 0) || fbi[AP].start <= 4 * K)
    {
        ILI_ERR("Content of fw file is broken. fbi[AP].start = 0x%x, fbi[AP].end = 0x%x, fbi[MP].end = 0x%x, block_num = %d\n",
                fbi[AP].start, fbi[AP].end, fbi[MP].end, block_num);
        return -1;
    }

    ILI_INFO("Content of fw file is correct\n");
    return 0;
}

int ili_fw_read_hw_crc(u32 start, u32 write_len, u32 *flash_crc)
{
    int retry = 100;
    u32 busy = 0;

    if (ili_ice_mode_write(FLASH0_CS, 0x0, 1) < 0)
        ILI_ERR("Write cs low failed\n");

    if (ili_ice_mode_write(FLASH1_KEY, 0x66aa55, 3) < 0)
        ILI_ERR("Write Flash key failed\n");

    if (ili_ice_mode_write(FLASH2_ADDR, 0x3B, 1) < 0)
        ILI_ERR("Write Fast Read 2X failed\n");

    if (ili_ice_mode_write(FLASH2_ADDR, (start & 0xFF0000) >> 16, 1) < 0)
        ILI_ERR("Write Set Address High failed\n");

    if (ili_ice_mode_write(FLASH2_ADDR, (start & 0x00FF00) >> 8, 1) < 0)
        ILI_ERR("Write Set Address Mid failed\n");

    if (ili_ice_mode_write(FLASH2_ADDR, start & 0x0000FF, 1) < 0)
        ILI_ERR("Write Set Address Low failed\n");

    if (ili_ice_mode_write(FLASH1_DUAL_MODE, 0x1, 1) < 0)
        ILI_ERR("Write Dual Mode On failed\n");

    if (ili_ice_mode_write(FLASH2_ADDR, 0xFF, 1) < 0)
        ILI_ERR("Write Dummy failed\n");

    if (ili_ice_mode_write(0x04100C, write_len, 3) < 0)
        ILI_ERR("Write Set Length failed\n");

    if (ili_ice_mode_write(0x048007, 0x02, 1) < 0)
        ILI_ERR("Write clearing int flag failed\n");

    if (ili_ice_mode_write(0x041016, 0x00, 1) < 0)
        ILI_ERR("Write 0x0 at 0x041016 failed\n");

    if (ili_ice_mode_write(0x041016, 0x01, 1) < 0)
        ILI_ERR("Write Checksum_En failed\n");

    if (ili_ice_mode_write(FLASH4_ADDR, 0xFF, 1) < 0)
        ILI_ERR("Write start to receive failed\n");

    do
    {
        if (ili_ice_mode_read(0x048007, &busy, sizeof(u8)) < 0)
            ILI_ERR("Read busy error\n");

        ILI_DBG("busy = %x, retry = %d\n", busy, retry);
        if (((busy >> 1) & 0x01) == 0x01)
            break;
        // msleep(POLLING_BUSY_DELAY_T);
    } while (--retry >= 0);

    if (ili_ice_mode_write(FLASH0_CS, 0x1, 1) < 0)
        ILI_ERR("Write CS high failed\n");

    if (retry <= 0)
    {
        ILI_ERR("Read HW CRC timeout !, busy = 0x%x\n", busy);
    }

    if (ili_ice_mode_write(FLASH1_DUAL_MODE, 0x0, 1) < 0)
        ILI_ERR("Write Dual Mode On failed\n");

    if (ili_ice_mode_read(0x04101C, flash_crc, sizeof(u32)) < 0)
    {
        ILI_ERR("Read hw crc error\n");
    }

    if (ili_ice_mode_write(FLASH0_CS, 0x1, 1) < 0)
        ILI_ERR("Write cs low failed\n");

    return 0;
}

static int ilitek_tddi_fw_read_flash_data(u32 start, u32 end, u8 *data, int len)
{
    u32 i, j, index = 0;
    u32 tmp;

    if (end - start > (u32)len)
    {
        ILI_ERR("the length (%d) reading crc is over than len(%d)\n", (int) (end - start), len);
        return -1;
    }

    if (ili_ice_mode_write(FLASH0_CS, 0x0, 1) < 0)
        ILI_ERR("Write cs low failed\n");

    if (ili_ice_mode_write(FLASH1_ADDR, 0x66aa55, 3) < 0)
        ILI_ERR("Write key failed\n");

    if (ili_ice_mode_write(FLASH2_ADDR, 0x03, 1) < 0)
        ILI_ERR("Write 0x3 failed\n");

    if (ili_ice_mode_write(FLASH2_ADDR, (start & 0xFF0000) >> 16, 1) < 0)
        ILI_ERR("Write address failed\n");

    if (ili_ice_mode_write(FLASH2_ADDR, (start & 0x00FF00) >> 8, 1) < 0)
        ILI_ERR("Write address failed\n");

    if (ili_ice_mode_write(FLASH2_ADDR, (start & 0x0000FF), 1) < 0)
        ILI_ERR("Write address failed\n");

    for (i = start, j = 0; i <= end; i++, j++)
    {
        if (ili_ice_mode_write(FLASH2_ADDR, 0xFF, 1) < 0)
            ILI_ERR("Write dummy failed\n");

        if (ili_ice_mode_read(FLASH4_ADDR, &tmp, sizeof(u8)) < 0)
            ILI_ERR("Read flash data error!\n");

        data[index] = tmp;
        index++;
        ilits.fw_update_stat = (j * 100) / len;
        ILI_DBG("Reading flash data .... %d%%\n", ilits.fw_update_stat);
        // msleep(POLLING_BUSY_DELAY_T);
    }

    if (ili_ice_mode_write(FLASH0_CS, 0x1, 1) < 0)
        ILI_ERR("Write cs high failed\n");

    return 0;
}

int ilitek_tddi_flash_fw_crc_check(void)
{
    int i, len = 0, crc_byte_len = 4;
    u8 flash_crc[4] = {0};
    u32 start_addr = 0, end_addr = 0;
    u32 hw_crc = 0;
    u32 flash_crc_cb = 0, hex_crc = 0;

    /* Check Flash and HW CRC */
    for (i = 0; i < FW_BLOCK_INFO_NUM; i++)
    {
        start_addr = fbi[i].start;
        end_addr = fbi[i].end;

        /* Invaild end address */
        if (end_addr == 0 || (i == BOOTLOADER && !ilits.flash_bl_en) )
            continue;

        ILI_DBG("block[%d], fbi[i].start = 0x%X, fbi[i].end = 0x%X, len = %X\n", i, fbi[i].start, fbi[i].end, (end_addr - start_addr - crc_byte_len + 1));
        if (ili_fw_read_hw_crc(start_addr, end_addr - start_addr - crc_byte_len + 1, &hw_crc) < 0)
        {
            ILI_ERR("Read HW CRC failed\n");
            return UPDATE_FAIL;
        }

        if (ilitek_tddi_fw_read_flash_data(end_addr - crc_byte_len + 1, end_addr, flash_crc, sizeof(flash_crc)) < 0)
        {
            ILI_ERR("Read Flash failed\n");
            return UPDATE_FAIL;
        }

        flash_crc_cb = flash_crc[0] << 24 | flash_crc[1] << 16 | flash_crc[2] << 8 | flash_crc[3];

        len = fbi[i].end - fbi[i].start + 1 - 4;
        hex_crc = CalculateCRC32(fbi[i].start, len, pfw);

        ILI_INFO("Block = %2d, HW CRC = 0x%08X, Flash CRC = 0x%08X, Hex CRC = 0x%08X\n", i, hw_crc, flash_crc_cb, hex_crc);

        if (hex_crc != hw_crc)
        {
            ILI_ERR("Hex and HW CRC not matched\n");
            return UPDATE_FAIL;
        }

        /* Compare Flash CRC with HW CRC */
        if (flash_crc_cb != hw_crc)
        {
            ILI_INFO("HW and Flash CRC not matched\n");
            return UPDATE_FAIL;
        }

        if (hex_crc != hw_crc)
        {
            ILI_ERR("Hex and HW CRC not matched\n");
            return UPDATE_FAIL;
        }
        memset(flash_crc, 0, sizeof(flash_crc));
    }

    ILI_INFO("Flash FW is the same as targe file FW\n");
    return UPDATE_PASS;
    return 0;
}

bool is_in_bootloader_mode(void)
{
    bool inbl_mode = DISABLE;
    u32 readData;

    // 進 Bootlaoder 會回應 00，用來判斷是否真的進到Bootloader
    ilits.wbuf[0] = 0xF6;
    ilits.wbuf[1] = 0x23;
    ilits.wrapper(ilits.wbuf, 2, NULL, 0);

    ilits.wbuf[0] = 0x23;
    ilits.wrapper(ilits.wbuf, 1, ilits.rbuf, 4);
    readData = (ilits.rbuf[READ_SHIFT] << 24) | (ilits.rbuf[READ_SHIFT + 1] << 16) | (ilits.rbuf[READ_SHIFT + 2] << 8) | ilits.rbuf[READ_SHIFT + 3];
    if (readData == 0)
    {
        // ILI_INFO("In bootloader mode.\n");
        inbl_mode = ENABLE;
    }
    else
    {
        // ILI_INFO("not bootloader mode.\n");
        inbl_mode = DISABLE;
    }

    return inbl_mode;
}

void ili_read_flash_info(void)
{
    int i = 0, flashIDIndex = 0, flashSignatureIndex = 0;
    u8 buf[3] = {0};
    u8 cmd = 0x9F;
    u32 tmp = 0;
    u32 flash_id = 0;
    u32 signature = 0;

    if (ili_ice_mode_write(FLASH_BASED_ADDR, 0x0, 1) < 0) /* CS Low */
        ILI_ERR("Write cs low failed\n");

    if (ili_ice_mode_write(FLASH1_ADDR, 0x66aa55, 3) < 0)
        ILI_ERR("Write key failed\n");

    if (ili_ice_mode_write(FLASH2_ADDR, cmd, 1) < 0) /* Read JEDEC ID */
        ILI_ERR("Write 0x9F failed\n");

    for (i = 0; i < (int)ARRAY_SIZE(buf); i++)
    {
        if (ili_ice_mode_write(FLASH2_ADDR, 0xFF, 1) < 0)
            ILI_ERR("Write dummy failed\n");

        if (ili_ice_mode_read(FLASH4_ADDR, &tmp, sizeof(u8)) < 0)
            ILI_ERR("Read flash info error\n");

        buf[i] = tmp;
    }

    if (ili_ice_mode_write(FLASH_BASED_ADDR, 0x1, 1) < 0) /* CS High */
        ILI_ERR("Write cs high failed\n");

    ilits.flash_mid = buf[0];
    ilits.flash_devid = buf[1] << 8 | buf[2];
    ilits.program_page = 2 * K;
    ilits.flash_sector = (4 * K);
    ilits.flashName = "";
    ilits.isSupportFlash = false;
    ilits.supportFlashIndex = 0;

    /* use Bootloader mode flash info */
    ILI_INFO("Flash MID = %x, Flash DEV_ID = %x\n", ilits.flash_mid, ilits.flash_devid);
    ILI_INFO("Flash program page = %d\n", ilits.program_page);
    ILI_INFO("Flash sector = %d\n", ilits.flash_sector);

    flash_id = (ilits.flash_mid << 16) + ilits.flash_devid;
    for (flashIDIndex = 0; flashIDIndex < (int)ARRAY_SIZE(flash_protect_list); flashIDIndex++)
    {
        if (flash_id == flash_protect_list[flashIDIndex].flashUID)
        {
            ilits.isSupportFlash = true;
            ilits.supportFlashIndex = flashIDIndex;
            break;
        }
    }

    if (flashIDIndex >= (int)ARRAY_SIZE(flash_protect_list))
        ILI_INFO("Not found flash id in table\n");
    else
    {
        if (flash_id == 0xC86013 || flash_id == 0xC84012)
        {                                                         /* special case, need to read flash signature */
            if (ili_ice_mode_write(FLASH_BASED_ADDR, 0x0, 1) < 0) /* CS Low */
                ILI_ERR("Write cs low failed\n");

            if (ili_ice_mode_write(FLASH1_ADDR, 0x66aa55, 3) < 0)
                ILI_ERR("Write key failed\n");

            /* read serial flash discoverable parameter (0x5A) */
            if (ili_ice_mode_write(FLASH2_ADDR, 0x5A, 1) < 0)
                ILI_ERR("Write 0x5A failed\n");

            /* signature address = 0x000000 */
            for (i = 0; i < 3; i++)
                if (ili_ice_mode_write(FLASH2_ADDR, 0x00, 1) < 0)
                    ILI_ERR("Write 0x00 failed\n");

            /* write 1 byte dummy */
            if (ili_ice_mode_write(FLASH2_ADDR, 0x00, 1) < 0)
                ILI_ERR("Write 0x00 failed\n");

            /* read 4 byte flash signature */
            for (i = 0; i < 4; i++)
            {
                if (ili_ice_mode_write(FLASH2_ADDR, 0xFF, 1) < 0)
                    ILI_ERR("Write dummy failed\n");

                if (ili_ice_mode_read(FLASH4_ADDR, &tmp, sizeof(u8)) < 0)
                    ILI_ERR("Read flash signature error\n");

                signature += (tmp << (i * 8));
            }

            if (ili_ice_mode_write(FLASH_BASED_ADDR, 0x1, 1) < 0) /* CS High */
                ILI_ERR("Write cs high failed\n");

            for (flashSignatureIndex = flashIDIndex; flashSignatureIndex < (int)ARRAY_SIZE(flash_protect_list); flashSignatureIndex++)
            {
                if (flash_id == flash_protect_list[flashSignatureIndex].flashUID)
                {
                    for (i = 0; i < flash_protect_list[flashSignatureIndex].flashSignatureCount; i++)
                    {
                        if (signature == flash_protect_list[flashSignatureIndex].flashSignature[i])
                            goto out;
                    }
                }
            }
        out:
            if (flashSignatureIndex >= (int)ARRAY_SIZE(flash_protect_list))
            {
                ilits.isSupportFlash = false;
                ILI_INFO("Not found flash signature (0x%X) in table\n", signature);
            }
            else
            {
                ilits.supportFlashIndex = flashSignatureIndex;
                ilits.flashName = flash_protect_list[flashSignatureIndex].name;
                ILI_INFO("Update Flash Name = %s, index = %d\n", ilits.flashName, ilits.supportFlashIndex);
            }
        }
        else
        { /* normal case */
            ilits.flashName = flash_protect_list[flashIDIndex].name;
            ILI_INFO("Flash Name = %s, index = %d\n", ilits.flashName, ilits.supportFlashIndex);
        }
    }
}

static void ili_tddi_flash_write_enable(void)
{
    if (ili_ice_mode_write(FLASH0_CS, 0x0, 1) < 0)
        ILI_ERR("Pull CS low failed\n");

    if (ili_ice_mode_write(FLASH1_KEY, 0x66aa55, 3) < 0)
        ILI_ERR("Write key failed\n");

    if (ili_ice_mode_write(FLASH2_ADDR, 0x6, 1) < 0)
        ILI_ERR("Write Write_En failed\n");

    if (ili_ice_mode_write(FLASH0_CS, 0x1, 1) < 0)
        ILI_ERR("Pull CS high failed\n");

    msleep(30);
}

int ili_polling_flash_busy(void)
{
    int retry = 100;
    u32 readData;

    do
    {
        // msleep(CMD_DELAY_T);
        if (ili_ice_mode_write(FLASH0_CS, 0x0, 1) < 0)
            ILI_ERR("Pull CS low failed\n");

        if (ili_ice_mode_write(FLASH1_KEY, 0x66aa55, 3) < 0)
            ILI_ERR("Write key failed\n");

        if (ili_ice_mode_write(FLASH2_ADDR, 0x5, 1) < 0)
            ILI_ERR("Write data failed\n");

        if (ili_ice_mode_write(FLASH2_ADDR, 0xFF, 1) < 0)
            ILI_ERR("Write dummy failed\n");

        if (ili_ice_mode_read(FLASH4_ADDR, &readData, 1) < 0)
            ILI_ERR("Read flash busy flag error\n");

        if (ili_ice_mode_write(FLASH0_CS, 0x1, 1) < 0)
            ILI_ERR("Pull CS low failed\n");

        if ((readData & 0x3) == 0x0)
        {
            ILI_INFO("polling flash busy pass\n");
            break;
        }
        else
        {
            ILI_INFO("polling flash busy, readData = 0x%X\n", readData);
        }
    } while (--retry >= 0);

    if (retry < 0)
    {
        ILI_ERR("check flash busy fail.\n");
        return RET_FAIL_NO;
    }
    return 0;
}

void ilitek_tddi_flash_read(u32 *data, u8 cmd, int len)
{
    u32 rxbuf[4] = {0};
    int i = 0;

    if (ili_ice_mode_write(FLASH_BASED_ADDR, 0x0, 1) < 0) /* CS Low */
        ILI_ERR("Write cs low failed\n");
    if (ili_ice_mode_write(FLASH1_ADDR, 0x66aa55, 3) < 0)
        ILI_ERR("Write key failed\n");

    if (ili_ice_mode_write(FLASH2_ADDR, cmd, 1) < 0)
        ILI_ERR("Write read command failed\n");
    for (i = 0; i < len; i++)
    {
        if (ili_ice_mode_write(FLASH2_ADDR, 0xFF, 1) < 0)
            ILI_ERR("Write read command failed\n");
        ili_ice_mode_read(FLASH4_ADDR, data, 1);
        rxbuf[i] = *data;
    }

    if (ili_ice_mode_write(FLASH_BASED_ADDR, 0x1, 1) < 0)
        ILI_ERR("Write cs high failed\n");

    *data = 0;
    if (len == 1)
        *data = rxbuf[0];
    else if (len == 2)
        *data = (rxbuf[0] | rxbuf[1] << 8);
    else if (len == 3)
        *data = (rxbuf[0] | rxbuf[1] << 8 | rxbuf[2] << 16);
    else
        *data = (rxbuf[0] | rxbuf[1] << 8 | rxbuf[2] << 16 | rxbuf[3] << 24);
    ILI_DBG("flash read data = 0X%X\n", *data);
}

void ilitek_tddi_flash_write(u8 cmd, u8 *sendbuf, int len)
{
    int i = 0;
    if (ili_ice_mode_write(FLASH_BASED_ADDR, 0x0, 1) < 0) /* CS Low */
        ILI_ERR("Write cs low failed\n");

    if (ili_ice_mode_write(FLASH1_ADDR, 0x66aa55, 3) < 0)
        ILI_ERR("Write key failed\n");

    if (ili_ice_mode_write(FLASH2_ADDR, cmd, 1) < 0)
        ILI_ERR("Write read command failed\n");

    for (i = 0; i < len; i++)
    {
        if (ili_ice_mode_write(FLASH2_ADDR, sendbuf[i], 1) < 0)
            ILI_ERR("Write sendbuf failed\n");
    }

    if (ili_ice_mode_write(FLASH_BASED_ADDR, 0x1, 1) < 0) /* CS high */
        ILI_ERR("Write cs high failed\n");
}

int ilitek_tddi_flash_protect(bool enable)
{
    int ret = 0, i = 0, w_count = 0, offsetIndex = 0;
    u32 flash_uid = 0, data = 0, ckreaddata = 0;
    u8 bitPosition = 0, setBitValue = 0;
    u8 w_buf[4] = {0};

    ILI_INFO("%s flash protection\n", enable ? "Enable" : "Disable");
    flash_uid = (ilits.flash_mid << 16) + ilits.flash_devid;

    if (flash_uid == 0x0)
    {
        ILI_ERR("flash_uid error, get flash info again!\n");
        ili_read_flash_info();
        flash_uid = (ilits.flash_mid << 16) + ilits.flash_devid;
    }

    ILI_INFO("flash(0x%X) is %s\n", flash_uid, ilits.isSupportFlash ? "supported" : "not supported");

    if (ilits.isSupportFlash)
    {
        /* read flash data */
        offsetIndex = 0;
        for (i = 0; i < flash_protect_list[ilits.supportFlashIndex].readOPCount; i++)
        {
            u32 tmp = 0;
            u8 cmd = flash_protect_list[ilits.supportFlashIndex].readOperator[i * 2];
            int readlen = flash_protect_list[ilits.supportFlashIndex].readOperator[(i * 2) + 1];
            ilitek_tddi_flash_read(&tmp, cmd, readlen);
            data |= tmp << (offsetIndex * 8);
            offsetIndex += readlen;
        }

        ILI_DBG("data = 0x%X\n", data);
        if (enable)
        {
            /* set flash all protect bit */
            for (i = 0; i < flash_protect_list[ilits.supportFlashIndex].protectAllOPCount; i++)
            {
                bitPosition = flash_protect_list[ilits.supportFlashIndex].protectAllOperator[i * 2];
                setBitValue = flash_protect_list[ilits.supportFlashIndex].protectAllOperator[(i * 2) + 1];

                if (setBitValue == 1)
                    data |= (0x1 << bitPosition);
                else
                    data &= ~(0x1 << bitPosition);
            }
        }
        else
        {
            int check_data_exist = OFF; // 假設陣列為空
            for (i = 0; i < (int)(sizeof(flash_protect_list[ilits.supportFlashIndex].protect_16K) / sizeof(flash_protect_list[ilits.supportFlashIndex].protect_16K[0])); i++)
            {
                if (flash_protect_list[ilits.supportFlashIndex].protect_16K[i] != 0)
                {
                    check_data_exist = ON; // 陣列不為空
                    break;
                }
            }

            if (flash_protect_list[ilits.supportFlashIndex].isSupportBootloader && check_data_exist == ON && !ilits.flash_bl_en)
            {
                ILI_INFO("set 16K non-protect\n");
                for (i = 0; i < flash_protect_list[ilits.supportFlashIndex].protect_16K_OPCount; i++)
                {
                    bitPosition = flash_protect_list[ilits.supportFlashIndex].protect_16K[i * 2];
                    setBitValue = flash_protect_list[ilits.supportFlashIndex].protect_16K[(i * 2) + 1];

                    if (setBitValue == 1)
                        data |= (0x1 << bitPosition);
                    else
                        data &= ~(0x1 << bitPosition);
                }
            }
            else
            {
                ILI_INFO("set all non-protect\n");
                for (i = 0; i < flash_protect_list[ilits.supportFlashIndex].resetOPCount; i++)
                {
                    bitPosition = flash_protect_list[ilits.supportFlashIndex].resetOperator[i * 2];
                    setBitValue = flash_protect_list[ilits.supportFlashIndex].resetOperator[(i * 2) + 1];

                    if (setBitValue == 1)
                        data |= (0x1 << bitPosition);
                    else
                        data &= ~(0x1 << bitPosition);
                }
            }
        }

        for (i = 0; i < 4; i++)
            w_buf[i] = (data >> (8 * i)) & 0xFF;

        ILI_DBG("write data = 0x%X\n", data);

        for (i = 0; i < flash_protect_list[ilits.supportFlashIndex].writeOPCount; i++)
        {
            u8 cmd = flash_protect_list[ilits.supportFlashIndex].writeOperator[i * 2];
            int writelen = flash_protect_list[ilits.supportFlashIndex].writeOperator[(i * 2) + 1];

            ili_tddi_flash_write_enable();

            ilitek_tddi_flash_write(cmd, &w_buf[w_count], writelen);

            if (ili_polling_flash_busy() < 0)
                ILI_ERR("pulling busy fail\n");
            w_count += writelen;
        }

        if (enable)
        {
            /* make sure the flash is protected  */
            ckreaddata = 0;

            offsetIndex = 0;
            for (i = 0; i < flash_protect_list[ilits.supportFlashIndex].readOPCount; i++)
            {
                u32 tmp = 0;
                u8 cmd = flash_protect_list[ilits.supportFlashIndex].readOperator[i * 2];
                int readlen = flash_protect_list[ilits.supportFlashIndex].readOperator[(i * 2) + 1];
                ilitek_tddi_flash_read(&tmp, cmd, readlen);
                ckreaddata |= tmp << (offsetIndex * 8);
                offsetIndex += readlen;
            }

            ILI_DBG("data = 0x%X, ckreaddata = 0x%X\n", data, ckreaddata);

            if (ckreaddata != data)
                ILI_ERR("protect flash fail, data = 0x%X, ckreaddata = 0x%X\n", data, ckreaddata);
        }
    }
    else
    {
        /*It only tries to unprotect flash in the unsupported list.*/
        if (enable)
        {
            ILI_ERR("no need to protect flash\n");
            goto out;
        }

        ili_tddi_flash_write_enable();
        msleep(30);

        if (ili_ice_mode_write(FLASH_BASED_ADDR, 0x0, 1) < 0) /* CS Low */
            ILI_ERR("Write cs low failed\n");
        if (ili_ice_mode_write(FLASH1_ADDR, 0x66aa55, 3) < 0)
            ILI_ERR("Write key failed\n");
        if (ili_ice_mode_write(FLASH2_ADDR, 0x01, 1) < 0)
            ILI_ERR("Write Start_Write failed\n");

        if (ili_ice_mode_write(FLASH2_ADDR, 0x00, 1) < 0)
            ILI_ERR("Write Un-Protect Low byte failed\n");
        if (ili_ice_mode_write(FLASH_BASED_ADDR, 0x1, 1) < 0)
            ILI_ERR("Write cs high failed\n");
    }
out:
    return ret;
}

static int ilitek_tddi_fw_flash_erase(void)
{
    int ret = 0, retry = TIMEOUT_SECTOR;
    u32 i = 0, addr = 0;
    u32 latch, pc;

    for (i = 0; i < FW_BLOCK_INFO_NUM; i++)
    {

        if (fbi[i].end == 0 || (i == BOOTLOADER && !ilits.flash_bl_en) )
            continue;

        if ((fbi[i].start < BOOTLOADER_BLOCK_END || fbi[i].end < BOOTLOADER_BLOCK_END ) && !ilits.flash_bl_en)
        {
            ILI_ERR("Invalid addr, Block[%d] : Erasing from (0x%08X) to (0x%08X)\n", (int) i, fbi[i].start, fbi[i].end);
            return UPDATE_FAIL;
        }

        ILI_INFO("Block[%2d]: Erasing from (0x%x) to (0x%x) \n", (int) i, fbi[i].start, fbi[i].end);

        for (addr = fbi[i].start; addr <= fbi[i].end; addr += ilits.flash_sector)
        {
            retry = TIMEOUT_SECTOR;
            ilits.wbuf[0] = 0x84;
            ilits.wbuf[1] = 0x06;
            ilits.wrapper(ilits.wbuf, 2, NULL, 0);

            ilits.wbuf[0] = 0x84;
            ilits.wbuf[1] = 0x20;
            ilits.wbuf[2] = (addr & 0xFF0000) >> 16;
            ilits.wbuf[3] = (addr & 0x00FF00) >> 8;
            ilits.wbuf[4] = (addr & 0x0000FF);
            ilits.wrapper(ilits.wbuf, 5, NULL, 0);

            // msleep(POLLING_BUSY_DELAY_T);
            do
            {
                // Flash Polling State
                ilits.wbuf[0] = 0x84;
                ilits.wbuf[1] = 0x05;
                ilits.wbuf[2] = 0xFF;

                ilits.wrapper(ilits.wbuf, 3, ilits.rbuf, 2);
                if (ilits.rbuf[READ_SHIFT - 1] == 0x84 && (ilits.rbuf[READ_SHIFT] & 0x03) == 0x00)
                {
                    ILI_DBG("polling pass check(0x1)\n");
                    break;
                }
                else
                {
                    ILI_DBG("polling fail check(0x1), ret = 0x%X\n", ilits.rbuf[READ_SHIFT]);
                }
            } while (--retry >= 0);

            if (retry < 0)
            {
                ILI_INFO("Erase Block[%d] fail, addr = 0x%08X, busy = %X\n", (int) i, addr, ilits.rbuf[READ_SHIFT]);
                msleep(WDT_DELAY_T);
                if (ili_ice_mode_read(TDDI_PC_COUNTER_ADDR, &pc, sizeof(u32)) < 0)
                    ILI_ERR("Read pc conter error\n");

                if (ili_ice_mode_read(TDDI_PC_LATCH_ADDR, &latch, sizeof(u32)) < 0)
                    ILI_ERR("Read pc latch error\n");

                ILI_ERR("erase polling fail, Read counter (addr: 0x%x) = 0x%x, latch (addr: 0x%x) = 0x%x\n",
                        TDDI_PC_COUNTER_ADDR, pc, TDDI_PC_LATCH_ADDR, latch);
                return UPDATE_FAIL;
            }
        }
    }
    msleep(WAIT_BL_FLASH_DONE_T);
    return ret;
}

static int ilitek_tddi_fw_flash_program(u8 *pfw)
{
    u8 buf[2100] = {0};
    u32 i = 0, addr = 0, k = 0;
    u32 page = (u32)ilits.program_page;
    int len, ret = 0;

    // Flash Program Pre CMD
    ilits.wbuf[0] = 0x80;
    ilits.wbuf[1] = 0x08; // Part_Size - 0x8:8K/0x1:256Byte/0x2:512Byte
    ilits.wbuf[2] = 0x80; // INDEX L, but no need this info
    ilits.wbuf[3] = 0x00; // INDEX H, but no need this info
    ilits.wrapper(ilits.wbuf, 4, NULL, 0);

    for (i = 0; i < FW_BLOCK_INFO_NUM; i++)
    {
        // ignore bootloader block
        if (fbi[i].end == 0 || (i == BOOTLOADER && !ilits.flash_bl_en) )
            continue;

        if ((fbi[i].start < BOOTLOADER_BLOCK_END || fbi[i].end < BOOTLOADER_BLOCK_END) && !ilits.flash_bl_en)
        {
            ILI_ERR("Invalid addr , Block[%2d] : Erasing from (0x%08X) to (0x%08X)\n", (int) i, fbi[i].start, fbi[i].end);
            return UPDATE_FAIL;
        }

        len = page + 13;
        ILI_INFO("Block[%2d]: Programing from (0x%x) to (0x%x), tfd.end_addr = 0x%x, page = %d\n",
                 (int) i, fbi[i].start, fbi[i].end, tfd.end_addr, (int) page);

        for (addr = fbi[i].start; addr < fbi[i].end; addr += page)
        {
            buf[0] = 0x05; // tool is 0x07 but spec is 0x05, FW don't cate this bytes
            buf[1] = 0xA4;
            buf[2] = len;
            buf[3] = len >> 8;
            buf[4] = 0x0;
            buf[5] = 0x0;
            buf[6] = 0x82;
            buf[7] = 0x08; // INDEX L, but no need this info
            buf[8] = 0x00; // INDEX H, but no need this info
            buf[9] = addr;
            buf[10] = addr >> 8;
            buf[11] = addr >> 16;

            for (k = 0; k < page; k++)
            {
                buf[12 + k] = pfw[addr + k];
            }

            buf[len - 1] = ili_calc_packet_checksum(buf, len - 2);

            ret = ioctl(ilits.fd_hidraw, HIDIOCSFEATURE(len), buf);
            if (ret < 0)
            {
                ILI_ERR("write hex data to flash error, retry it\n");
                msleep(WAIT_BL_FLASH_DONE_T);
                ret = ioctl(ilits.fd_hidraw, HIDIOCSFEATURE(len), buf);
                if (ret < 0)
                    ILI_ERR("write hex data to flash error\n");
                // return -EFW_PROGRAM;
            }
            msleep(POLLING_BUSY_DELAY_T);
            // 100 * (addr - fbi[i].start) / (fbi[i].end - fbi[i].start)

            ILI_DBG("Program flahse data .... %d%%\n", (int) (100 * (addr - fbi[i].start) / (fbi[i].end - fbi[i].start)));
        }
    }
    msleep(WAIT_BL_FLASH_DONE_T);
    return 0;
}

int get_info(void)
{
    u32 readData;

    // Read chip ID
    readData = 0;
    ili_ice_mode_write(FLASH0_CS, 0x1, 1); // CS High
    ili_ice_mode_write(FLASH0_CS, 0x0, 1); // CS Low
    ili_ice_mode_read(TDDI_PID_ADDR, &readData, 4);
    ILI_INFO("chip = %X\n", (readData >> 8));
    if (readData == 0)
    {
        ILI_ERR("chip ID ERROR!!!\n");
        return RET_FAIL_NO;
    }

    ili_ice_mode_write(FLASH0_CS, 0x1, 1); // CS High
    // use bootloader mode flash info again, so no need
    // ili_read_flash_info();

    // AP to BL CMD
    ilits.wbuf[0] = 0x8E;
    ilits.wrapper(ilits.wbuf, 1, NULL, 0);
    msleep(MODE_CHANGE_DELAY_T);

    // Read Bootloader Version
    ilits.wbuf[0] = 0x81;
    ilits.wrapper(ilits.wbuf, 1, ilits.rbuf, 5);
    ilits.chip.bl_ver = (ilits.rbuf[READ_SHIFT] << 24) | (ilits.rbuf[READ_SHIFT + 1] << 16) | (ilits.rbuf[READ_SHIFT + 2] << 8) | ilits.rbuf[READ_SHIFT + 3];

    ILI_INFO("Bootloader Version = %d.%d.%d.%d\n", ilits.rbuf[READ_SHIFT], ilits.rbuf[READ_SHIFT + 1], ilits.rbuf[READ_SHIFT + 2], ilits.rbuf[READ_SHIFT + 3]);
    if (ilits.chip.bl_ver == 0)
    {
        ILI_ERR("Bootloader Version ERROR!!!\n");
        return RET_FAIL_NO;
    }
    // // Read Flash ID CMD
    // ilits.wbuf[0] = 0x84;
    // ilits.wbuf[1] = 0x9F;
    // ilits.wrapper(ilits.wbuf, 2, ilits.rbuf, 4);
    // ilits.flash_mid = ilits.rbuf[READ_SHIFT];
    // ilits.flash_devid = (ilits.rbuf[READ_SHIFT + 1] << 8 | ilits.rbuf[READ_SHIFT + 2]);
    // ilits.flash_sector = 4 * K;
    // ilits.program_page = 2 * K;
    // ILI_INFO("read flash in boot loader : flash mid = 0x%X, devices id = %X\n", ilits.flash_mid, ilits.flash_devid);

    // if (ilits.flash_mid == 0 || ilits.flash_devid == 0)
    // {
    //     ILI_ERR("Flash Information ERROR!!!\n");
    //     return RET_FAIL_NO;
    // }
    ili_read_flash_info();

    ILI_INFO("check FW, current is in %s mode\n", (is_in_bootloader_mode()) ? "BL" : "AP");

    return 0;
}

static void ilitek_tddi_fw_update_block_info(u8 *pfw)
{
    u32 fw_info_addr = 0, fw_mp_ver_addr = 0;

    fbi[AP].name = "AP";
    fbi[DATA].name = "DATA";
    fbi[TUNING].name = "TUNING";
    fbi[MP].name = "MP";
    fbi[GESTURE].name = "GESTURE";

    /* upgrade mode define */
    fbi[DATA].mode = fbi[AP].mode = fbi[TUNING].mode = AP;
    fbi[MP].mode = MP;
    fbi[GESTURE].mode = GESTURE;

    if (fbi[AP].end > (64 * K))
        tfd.is80k = true;

    /* Copy fw info */
    fw_info_addr = fbi[AP].end - INFO_HEX_ST_ADDR;
    ILI_INFO("Parsing hex info start addr = 0x%x\n", fw_info_addr);
    ipio_memcpy(ilits.fw_info, (pfw + fw_info_addr), sizeof(ilits.fw_info), sizeof(ilits.fw_info));

    /* copy fw mp ver */
    fw_mp_ver_addr = fbi[MP].end - INFO_MP_HEX_ADDR;
    ILI_INFO("Parsing hex mp ver addr = 0x%x\n", fw_mp_ver_addr);
    ipio_memcpy(ilits.fw_mp_ver, pfw + fw_mp_ver_addr, sizeof(ilits.fw_mp_ver), sizeof(ilits.fw_mp_ver));

    /* copy fw core ver */
    ilits.chip.core_ver = (ilits.fw_info[68] << 24) | (ilits.fw_info[69] << 16) |
                          (ilits.fw_info[70] << 8) | ilits.fw_info[71];
    ILI_INFO("New FW Core version = %x\n", ilits.chip.core_ver);

    /* Get hex fw vers */
    tfd.new_fw_cb = (ilits.fw_info[48] << 24) | (ilits.fw_info[49] << 16) |
                    (ilits.fw_info[50] << 8) | ilits.fw_info[51];

    /* Get hex report info block*/
    ipio_memcpy(&ilits.rib, ilits.fw_info, sizeof(ilits.rib), sizeof(ilits.rib));
    ilits.rib.nReportResolutionMode = ilits.rib.nReportResolutionMode & 0x07;
    // ilits.rib.nCustomerType = ilits.rib.nCustomerType;
    ILI_INFO("report_info_block : nReportByPixel = %d, nIsHostDownload = %d, nIsSPIICE = %d, nIsSPISLAVE = %d\n",
             ilits.rib.nReportByPixel, ilits.rib.nIsHostDownload, ilits.rib.nIsSPIICE, ilits.rib.nIsSPISLAVE);
    ILI_INFO("report_info_block : nIsI2C = %d, nReserved00 = %d, nCustomerType = %d, nReportResolutionMode = %d, nReserved02 = %x,  nReserved03 = %x\n",
             ilits.rib.nIsI2C, ilits.rib.nReserved00, ilits.rib.nCustomerType, ilits.rib.nReportResolutionMode, ilits.rib.nReserved02, ilits.rib.nReserved03);

    /* Calculate update address */
    ILI_INFO("New FW ver = 0x%x\n", tfd.new_fw_cb);
    ILI_INFO("star_addr = 0x%06X, end_addr = 0x%06X, Block Num = %d\n", tfd.start_addr, tfd.end_addr, tfd.block_number);
}

static int ilitek_tddi_fw_hex_convert(u8 *phex, u32 size, u8 *pfw)
{
    int block = 0;
    u32 i = 0, j = 0, k = 0, num = 0;
    u32 len = 0, addr = 0, type = 0;
    u32 start_addr = 0x0, end_addr = 0x0, ex_addr = 0;
    u32 offset;
    char signstr[258] = { 0 };

    memset(fbi, 0x0, sizeof(fbi));

    /* Parsing HEX file */
    for (; i < size;)
    {
        len = HexToDec(&phex[i + 1], 2);
        addr = HexToDec(&phex[i + 3], 4);
        type = HexToDec(&phex[i + 7], 2);

        if (type == 0x04)
        {
            ex_addr = HexToDec(&phex[i + 9], 4);
        }
        else if (type == 0x02)
        {
            ex_addr = HexToDec(&phex[i + 9], 4);
            ex_addr = ex_addr >> 12;
        }
        else if (type == BLOCK_TAG_AF)
        {
            /* insert block info extracted from hex */
            tfd.hex_tag = type;
            if (tfd.hex_tag == BLOCK_TAG_AF)
                num = HexToDec(&phex[i + 9 + 6 + 6], 2);
            else
                num = 0xFF;

            if (num > (FW_BLOCK_INFO_NUM - 1))
            {
                ILI_ERR("ERROR! block num is larger than its define (%d, %d)\n",
                        (int) num, FW_BLOCK_INFO_NUM - 1);
                return -EINVAL;
            }

            fbi[num].start = HexToDec(&phex[i + 9], 6);
            fbi[num].end = HexToDec(&phex[i + 9 + 6], 6);
            fbi[num].fix_mem_start = INT_MAX;
            fbi[num].len = fbi[num].end - fbi[num].start + 1;
            ILI_INFO("Block[%d]: start_addr = %x, end = %x\n", (int) num, fbi[num].start, fbi[num].end);

            block++;
        }
        else if (type == BLOCK_TAG_B0 && tfd.hex_tag == BLOCK_TAG_AF)
        {
            num = HexToDec(&phex[i + 9 + 6], 2);

            if (num > (FW_BLOCK_INFO_NUM - 1))
            {
                ILI_ERR("ERROR! block num is larger than its define (%d, %d)\n",
                        (int) num, FW_BLOCK_INFO_NUM - 1);
                return -EINVAL;
            }

            fbi[num].fix_mem_start = HexToDec(&phex[i + 9], 6);
            ILI_INFO("Tag 0xB0: change Block[%d] to addr = 0x%x\n", (int) num, fbi[num].fix_mem_start);
        } else if (type == BLOCK_TAG_BLKEY) {	/* checking hex file signature */
			for (j = 0, k = 0; j < (len * 2); j += 2, k++)
				signstr[k] = (char) HexToDec(&phex[i + 9 + j], 2);
			signstr[k] = '\0';
			ILI_DBG("hex sign = [%s]\n", signstr);
			if (strcmp(signstr, HEX_CHK_KEY2) == 0) {
				ILI_INFO("hex file support flash key.\n");
				ilits.flash_bl_key_en = ENABLE;
			}
		}


        addr = addr + (ex_addr << 16);

        if (phex[i + 1 + 2 + 4 + 2 + (len * 2) + 2] == 0x0D)
            offset = 2;
        else
            offset = 1;

        if (addr >= MAX_HEX_FILE_SIZE)
        {
            ILI_ERR("Invalid hex format %d\n", (int) addr);
            return -1;
        }

        if (type == 0x00)
        {
            end_addr = addr + len;
            if (addr < start_addr)
                start_addr = addr;
            /* fill data */
            for (j = 0, k = 0; j < (len * 2); j += 2, k++)
                pfw[addr + k] = HexToDec(&phex[i + 9 + j], 2);
        }
        i += 1 + 2 + 4 + 2 + (len * 2) + 2 + offset;
    }

    if (ilitek_fw_calc_file_crc(pfw) < 0)
        return -1;

    tfd.start_addr = start_addr;
    tfd.end_addr = end_addr;
    tfd.block_number = block;
    return 0;
}

static void check_flash_boolloader(u8 *key)
{
    if ((strcmp((const char *) key, HEX_CHK_KEY1) == 0)
        && (ilits.flash_bl_key_en == ENABLE)) {
        ILI_INFO("***flash bootloader code***\n");
        ilits.flash_bl_en = ENABLE;
    } else {
        ilits.flash_bl_en = DISABLE;
    }
}

static int ilitek_tdd_fw_hex_open(u8 *pfw)
{
    int ret = 0, fsize = 0;
    int f;

    f = open(ilits.md_fw_filp_path, O_RDONLY);

    if (f < 0)
    {
        close(f);
        return -EMP_FILE;
    }

    // get file size
    fsize = get_file_size(ilits.md_fw_filp_path);
    ILI_INFO("fsize = %d\n", fsize);

    ipio_free((void **)&(ilits.tp_fw.data));
    ilits.tp_fw.size = fsize;

    ilits.tp_fw.data = (u8 *)malloc(fsize);
    if (!ilits.tp_fw.data)
    {
        ret = -EFAULT;
        goto out;
    }

    (void)read(f, (void *)ilits.tp_fw.data, fsize);

    /* Convert hex and copy data from tp_fw.data to pfw */
    if (ilitek_tddi_fw_hex_convert((u8 *)ilits.tp_fw.data, (u32)ilits.tp_fw.size, pfw) < 0)
    {
        ILI_ERR("Convert hex file failed\n");
        ret = -1;
        goto out;
    }

    check_flash_boolloader(ilits.data);

    ilitek_tddi_fw_update_block_info(pfw);
out:
    close(f);

    ipio_free((void **)&(ilits.tp_fw.data));
    return ret;
}

int open_hex(char *file_path)
{
    int i;
    ipio_free((void **)&pfw);

    pfw = (u8 *)malloc(MAX_HEX_FILE_SIZE * sizeof(u8));

    if (!pfw)
    {
        ILI_ERR("Failed to allocate pfw memory\n");
        return -ENOMEM;
    }

    for (i = 0; i < MAX_HEX_FILE_SIZE; i++)
        pfw[i] = 0xFF;

    ilits.md_fw_filp_path = file_path;
    ILI_INFO("open hex path : %s\n", ilits.md_fw_filp_path);

    if (ilitek_tdd_fw_hex_open(pfw) < 0)
    {
        ILI_ERR("Open hex file fail\n");
        return -EMP_FILE;
    }
    return 0;
}

int check_fw_crc(char *hex_path)
{
    int ret = RET_FAIL;
    ILI_INFO("check crc hex path = %s\n", hex_path);
    switch_bootloader();
    if (open_hex(hex_path) < 0)
    {
        ILI_ERR("error file : %s\n", hex_path);
        ret = RET_FAIL;
        goto out;
    }
    ret = ilitek_tddi_flash_fw_crc_check();
out:
    ipio_free((void **)&pfw);
    ili_ic_whole_reset(ON);
    return ret;
}

int do_fw_upgrade(void)
{
    // u8 cmdbuf[64] = {0};
    // u32 readData, write_len;
    int ret = UPDATE_PASS;

    ili_ic_disable_report();

    if (get_info() < 0)
    {
        ILI_ERR("get info fail.\n");
        return UPDATE_FAIL;
    }

    if (ilitek_tddi_flash_protect(DISABLE) < 0)
    {
        ILI_ERR("flash protect fail.\n");
        goto out;
    }

    ret = ilitek_tddi_fw_flash_erase();
    if (ret < 0)
    {
        ILI_ERR("erase flash fail.\n");
        goto out;
    }

    ret = ilitek_tddi_fw_flash_program(pfw);
    if (ret < 0)
    {
        ILI_ERR("erase flash fail.\n");
        goto out;
    }

    ret = ilitek_tddi_flash_fw_crc_check();

out:
    ilitek_tddi_flash_protect(ENABLE);
    ili_ic_whole_reset(ON);
    ili_ic_get_protocl_ver();
    ili_ic_get_core_ver();
    ili_ic_get_fw_ver(true);
    ipio_free((void **)&pfw);
    return ret;
}

int do_fw_upgrade_test(void)
{
    // u8 cmdbuf[64] = {0};
    int ret = UPDATE_PASS;

    ili_ic_disable_report();
    ili_ic_set_engineer_mode();

    if (get_info() < 0)
    {
        ILI_ERR("get info fail.\n");
        return RET_FAIL_NO;
    }

    ilitek_tddi_flash_protect(DISABLE);

    // ret = ilitek_tddi_fw_flash_erase();
    // if (ret < 0)
    // {
    //     ILI_ERR("erase flash fail.\n");
    //     goto out;
    // }

    // ret = ilitek_tddi_fw_flash_program(pfw);
    // if (ret < 0)
    // {
    //     ILI_ERR("erase flash fail.\n");
    //     goto out;
    // }

    // // ILI_INFO("check BL mode = %d\n", is_in_bootloader_mode());
    // ret = ilitek_tddi_flash_fw_crc_check();

    ilitek_tddi_flash_protect(ENABLE);
    ili_ic_whole_reset(ON);
    // ili_ic_get_protocl_ver();
    // ili_ic_get_core_ver();
    ili_ic_get_fw_ver(true);
    ipio_free((void **)&pfw);
    return ret;
}
