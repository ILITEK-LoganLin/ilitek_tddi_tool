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

/* Debug level */
bool log_en = ENABLE;
bool debug_log_en = DISABLE;

struct ilitek_ts_data ilits;
struct hidraw_report_descriptor report_desc;
struct hidraw_devinfo info;

size_t TimeoutRead(int port, void *buf, size_t size, int mlsec_timeout)
{
    struct pollfd fd = {.fd = port, .events = POLLIN};

    size_t bytesread = 0;

    while (poll(&fd, 1, mlsec_timeout) == 1)
    {
        int chunksize = read(port, buf + bytesread, size);
        if (chunksize == -1)
            return -1;

        bytesread += chunksize;
        size -= chunksize;

        if (size == 0)
            return bytesread;
    }

    return bytesread;
}

int open_hid_node(void)
{
    ILI_DBG("open node\n");
    if (ilits.fd_hidraw > 0)
    {
        ILI_INFO("close ilits.fd_hidraw before open it.\n");
        close(ilits.fd_hidraw);
    }
    /* Open the Device with non-blocking reads. In real life,
           don't use a hard coded path; use libudev instead. */
    // ilits.fd_hidraw = open(HID_RAW_NODE, O_RDWR | O_NONBLOCK);
    ilits.fd_hidraw = open(HID_RAW_NODE, O_RDWR);

    if (ilits.fd_hidraw <= 0)
    {
        printf("can't open %s, fd: %d, err: %d\n",
               HID_RAW_NODE, ilits.fd_hidraw, errno);
        return RET_FAIL_NO;
    }

    return 0;
}

void close_hid_node(void)
{
    ILI_DBG("close node\n");
    if (ilits.fd_hidraw > 0)
        close(ilits.fd_hidraw);
    ilits.fd_hidraw = 0;
}

void init_hid(void)
{
    ipio_free((void **)&ilitsmp);
    memset(&ilits, 0x0, sizeof(struct ilitek_ts_data));
    memset(&report_desc, 0x0, sizeof(report_desc));
    memset(&info, 0x0, sizeof(info));
    ilits.wrapper = ili_i2c_wrapper;

    debug_log_en = DISABLE;
    strcpy(ilits.fw_path, DEF_FW_FILP_PATH);
    strcpy(ilits.save_path, DEF_MP_LCM_ON_PATH);
    strcpy(ilits.ini_path, DEF_INI_FILP_PATH);
}

void check_hidraw_info(void)
{
    int i, res, desc_size = 0;
    char buf[256];

    ILI_INFO("check_hidraw_info\n");

    res = ioctl(ilits.fd_hidraw, HIDIOCGRDESCSIZE, &desc_size);
    if (res < 0)
    {
        ILI_ERR("HIDIOCGRDESCSIZE error\n");
    }
    else
    {
        ILI_INFO("[%s] fd: %d, desc size: %d\n", HID_RAW_NODE, ilits.fd_hidraw, desc_size);
        /* Get Report Descriptor */
        report_desc.size = desc_size;
    }

    /* Get Raw Name */
    res = ioctl(ilits.fd_hidraw, HIDIOCGRDESC, &report_desc);
    if (res < 0)
    {
        ILI_ERR("HIDIOCGRDESC error\n");
    }
    else
    {
        printf("Report Descriptor:\n");
        for (i = 0; i < report_desc.size; i++)
            printf("%hhx ", report_desc.value[i]);
        puts("\n");
    }

    /* Get Raw Name */
    memset(&buf, 0x0, sizeof(buf));
    res = ioctl(ilits.fd_hidraw, HIDIOCGRAWNAME(256), buf);
    if (res < 0)
    {
        ILI_ERR("HIDIOCGRAWNAME error\n");
    }
    else
    {
        ILI_INFO("Raw Name: %s\n", buf);
    }

    /* Get Physical Location */
    memset(&buf, 0x0, sizeof(buf));
    res = ioctl(ilits.fd_hidraw, HIDIOCGRAWPHYS(256), buf);
    if (res < 0)
    {
        ILI_ERR("HIDIOCGRAWPHYS error\n");
    }
    else
    {
        ILI_INFO("Raw Phys: %s\n", buf);
    }

    /* Get Raw Info */
    memset(&buf, 0x0, sizeof(buf));
    res = ioctl(ilits.fd_hidraw, HIDIOCGRAWINFO, buf);
    if (res < 0)
    {
        ILI_ERR("HIDIOCGRAWINFO error\n");
    }
    else
    {
        ILI_INFO("Raw Info:\n");
        ILI_INFO("\tbustype: %d\n", info.bustype);
        ILI_INFO("\tvendor: 0x%04hx\n", info.vendor);
        ILI_INFO("\tproduct: 0x%04hx\n", info.product);
    }

    /* Get Device Name */
    memset(&buf, 0x0, sizeof(buf));
    res = ioctl(ilits.fd_hidraw, HIDIOCGRAWNAME(256), buf);
    if (res < 0)
    {
        ILI_ERR("HIDIOCGRAWNAME error\n");
    }
    else
    {
        ILI_INFO("devices name: %s\n", buf);
    }
}

int ili_i2c_wrapper(u8 *txbuf, u32 wlen, u8 *rxbuf, u32 rlen)
{
    int ret = 0, operate = -1, index = 0;
    char wdata[256] = {0};

    if (wlen > 0 && rlen > 0)
        operate = RW_SYNC;
    else if (wlen > 0 && !rlen)
        operate = W_ONLY;
    else
        operate = R_ONLY;

    if (operate == RW_SYNC || operate == W_ONLY)
    {
        wdata[0] = 0x03;
        wdata[1] = 0xA3;
        wdata[2] = wlen & 0xff;
        wdata[3] = rlen & 0xff;
        index = 4;
        if (rlen > 0xFF) {
            wdata[3] = 0;
        }
    }
    else
    {
        index = 1;
    }

    if (rlen > 0)
        rlen += 3;
    wlen += 4;

    switch (operate)
    {
    case RW_SYNC:
    case W_ONLY:
        ipio_memcpy(&wdata[index], txbuf, wlen, wlen);
        ili_dump_data(wdata, 8, wlen, 256, "wdata:");
        ret = ioctl(ilits.fd_hidraw, HIDIOCSFEATURE(wlen), wdata);
        if (ret < 0)
        {
            ILI_ERR("write hidraw error\n");
            break;
        }

        if (operate == W_ONLY)
        {
            msleep(CMD_DELAY_T);
            break;
        }

    case R_ONLY:
        if (rlen > 64)
        {
            ret = (int)TimeoutRead(ilits.fd_hidraw, rxbuf, 10, MP_INT_TIMEOUT);
            if (rlen <= 1500)
            {
                rxbuf[0] = 0x6; /* Report Number */
                rlen = 1500;
            }
            else if (rlen > 1500 && rlen < 2177)
            {
                rxbuf[0] = 0x7; /* Report Number */
                rlen = 2177;
            }
            else
            {
                rxbuf[0] = 0x9; /* Report Number */
                // rlen = 6000;
                rlen = 4080;
            }
            ret = ioctl(ilits.fd_hidraw, HIDIOCGFEATURE(rlen), rxbuf);
            if (ret < 0) {
                ILI_ERR("retry HIDIOCGFEATURE\n");
                msleep(1000);
                ret = ioctl(ilits.fd_hidraw, HIDIOCGFEATURE(rlen), rxbuf);
            }
        }
        else
        {
            ret = (int)TimeoutRead(ilits.fd_hidraw, rxbuf, rlen, AP_INT_TIMEOUT);

            if (ret == 0)
            {
                ILI_ERR("read hidraw timeout, cmd header : 0x%02X\n", wdata[4]);
                ret = RET_FAIL_NO;
            }
        }

        if (ret < 0)
        {
            ILI_ERR("read hidraw error\n");
        }
        ili_dump_data(rxbuf, 8, rlen, 256, "rxbuf:");
        msleep(CMD_DELAY_T);
        break;
    default:
        ILI_ERR("Unknown ts-i2c operation\n");
        ret = -EINVAL;
        break;
    }
    return ret;
}

int ili_ice_mode_write(u32 addr, u32 data, int len)
{

    int ret = 0, i;
    u8 txbuf[16] = {0};

    for (i = 0; i < len; i++)
        txbuf[i + 8] = (char)(data >> (8 * i));

    txbuf[0] = 0x03;
    txbuf[1] = 0xA3;
    txbuf[2] = (len + 4) & 0xFF;
    txbuf[3] = 0x0;
    txbuf[4] = 0x25;
    txbuf[5] = (char)((addr & 0x000000FF) >> 0);
    txbuf[6] = (char)((addr & 0x0000FF00) >> 8);
    txbuf[7] = (char)((addr & 0x00FF0000) >> 16);
    ili_dump_data(txbuf, 8, (8 + len), 256, "ice write buf:");
    ret = ioctl(ilits.fd_hidraw, HIDIOCSFEATURE(8 + len), txbuf);
    msleep(CMD_DELAY_T); // if no delay, it only 100 us. so delay 1 ms
    return ret;
}

int ili_ice_mode_read(u32 addr, u32 *data, int len)
{
    int ret = 0;
    u8 rxbuf[8] = {0};
    u8 txbuf[8] = {0};

    if (len > sizeof(u32))
    {
        ILI_ERR("ice mode read lenght = %d, must less than or equal to 4 bytes\n", len);
        len = 4;
    }

    txbuf[0] = 0x03;
    txbuf[1] = 0xA3;
    txbuf[2] = 0x04;             // write len
    txbuf[3] = (len + 4) & 0xFF; // read len
    txbuf[4] = 0x25;
    txbuf[5] = (char)((addr & 0x000000FF) >> 0);
    txbuf[6] = (char)((addr & 0x0000FF00) >> 8);
    txbuf[7] = (char)((addr & 0x00FF0000) >> 16);
    ili_dump_data(txbuf, 8, 8, 256, "ice read wbuf:");
    ret = ioctl(ilits.fd_hidraw, HIDIOCSFEATURE(8), txbuf);
#if 1
    ret = (int)TimeoutRead(ilits.fd_hidraw, rxbuf, 4 + len, AP_INT_TIMEOUT);
    if (ret == 0)
    {
        ILI_ERR("timeout to ice mode read, ret = %d\n", ret);
        ret = RET_FAIL_NO;
    }
    else if (ret < 0)
    {
        ILI_ERR("Failed to read data in ice mode, ret = %d\n", ret);
    }
#else
    msleep(CMD_DELAY_T);

    ret = ioctl(ilits.fd_hidraw, HIDIOCGFEATURE(4 + len), rxbuf);
    if (ret < 0)
        ILI_ERR("Failed to read data in ice mode, ret = %d\n", ret);
#endif
    ili_dump_data(rxbuf, 8, (4 + len), 256, "ice read rbuf:");
    *data = 0;
    if (len == 1)
        *data = rxbuf[4];
    else if (len == 2)
        *data = (rxbuf[4] | rxbuf[5] << 8);
    else if (len == 3)
        *data = (rxbuf[4] | rxbuf[5] << 8 | rxbuf[6] << 16);
    else
        *data = (rxbuf[4] | rxbuf[5] << 8 | rxbuf[6] << 16 | rxbuf[7] << 24);
    msleep(CMD_DELAY_T);
    return ret;
}

void ili_dump_data(void *data, int type, int len, int row_len, const char *name)
{
    int i, row = 31;
    u8 *p8 = NULL;
    s32 *p32 = NULL;
    s16 *p16 = NULL;

    if (!debug_log_en)
        return;

    if (row_len > 0)
        row = row_len;

    if (data == NULL)
    {
        ILI_ERR("The data going to dump is NULL\n");
        return;
    }

    printf("ILITEK: Dump %s data\n", name);
    printf("ILITEK: ");

    if (type == 8)
        p8 = (u8 *)data;
    if (type == 32 || type == 10)
        p32 = (s32 *)data;
    if (type == 16)
        p16 = (s16 *)data;

    for (i = 0; i < len; i++)
    {
        if (type == 8)
            printf(" %02X ", p8[i]);
        else if (type == 32)
            printf(" %4x ", p32[i]);
        else if (type == 10)
            printf(" %4d ", p32[i]);
        else if (type == 16)
            printf(" %4d ", p16[i]);

        if ((i % row) == row - 1)
        {
            printf("\n");
            printf("ILITEK: ");
        }
    }
    printf("\n");
}

void ili_ic_whole_reset(bool withflash)
{
    ILI_INFO("whole reset, withflash = %d\n", withflash);
    if (withflash)
        ilits.chip.reset_key = TDDI_WHOLE_CHIP_RST_WITH_FLASH_KEY;
    else
        ilits.chip.reset_key = TDDI_WHOLE_CHIP_RST_WITHOUT_FLASH_KEY;
    ili_ice_mode_write(TDDI_CHIP_RESET_ADDR, ilits.chip.reset_key, 4);
    msleep(RST_DELAY_T);
}
