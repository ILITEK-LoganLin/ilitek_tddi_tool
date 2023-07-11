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
#include "MP/ilitek_mp.h"

u8 debug_ret = RET_PASS;
static int testcase;

enum TESTCASE
{
    UNKNOWN = 0,
    FW_UPGRADE,
    MP_LCM_ON,
    MP_LCM_OFF,
    RESET,
    FWVER,
    CK_BL,
    ISTDDI,
    DAEMON_VER,
    CHECK_CRC,
    VER_INFO,
    WRITE_TP_REG,
    READ_TP_REG,
    WRITE_DDI_REG,
    READ_DDI_REG,
    SWITCH_AP_MODE,
    SWITCH_MP_MODE,
    SWITCH_BL_MODE,
    HID_INFO,
    DIS_REPORT,
    EN_REPORT,
};

enum PATHCASE
{
    PATH = 50,
    INI_PATH,
    LOG_FILE_PATH,
    INPUT_DATA,
    HID_NODE,
    FLAG,
};

void removeCR(char *str) {
    size_t length = strlen(str);
    if (length > 0 && str[length - 1] == 13) {
        str[length - 1] = '\0';
    }
}

int get_test_case(char *name)
{
    int ret;
    if (strcmp(name, "FWUpgrade") == 0)
    {
        ret = FW_UPGRADE;
    }
    else if (strcmp(name, "mp_lcmon") == 0)
    {
        ret = MP_LCM_ON;
    }
    else if (strcmp(name, "mp_lcmoff") == 0)
    {
        ret = MP_LCM_OFF;
    }
    else if (strcmp(name, "Reset") == 0)
    {
        ret = RESET;
    }
    else if (strcmp(name, "GetFWVer") == 0)
    {
        ret = FWVER;
    }
    else if (strcmp(name, "check_bl_mode") == 0)
    {
        ret = CK_BL;
    }
    else if (strcmp(name, "IsTDDI") == 0)
    {
        ret = ISTDDI;
    }
    else if (strcmp(name, "version") == 0 || strcmp(name, "ver") == 0)
    {
        ret = DAEMON_VER;
    }
    else if (strcmp(name, "CheckCRC") == 0)
    {
        ret = CHECK_CRC;
    }
    else if (strcmp(name, "ver_info") == 0)
    {
        ret = VER_INFO;
    }
    else if (strcmp(name, "w_tp_reg") == 0)
    {
        ret = WRITE_TP_REG;
    }
    else if (strcmp(name, "r_tp_reg") == 0)
    {
        ret = READ_TP_REG;
    }
    else if (strcmp(name, "w_ddi_reg") == 0)
    {
        ret = WRITE_DDI_REG;
    }
    else if (strcmp(name, "r_ddi_reg") == 0)
    {
        ret = READ_DDI_REG;
    }
    else if (strcmp(name, "switchap") == 0)
    {
        ret = SWITCH_AP_MODE;
    }
    else if (strcmp(name, "switchmp") == 0)
    {
        ret = SWITCH_MP_MODE;
    }
    else if (strcmp(name, "switchbl") == 0)
    {
        ret = SWITCH_BL_MODE;
    }
    else if (strcmp(name, "GetHIDInfo") == 0)
    {
        ret = HID_INFO;
    }
    else if (strcmp(name, "disablereport") == 0 || strcmp(name, "dis_rpt") == 0)
    {
        ret = DIS_REPORT;
    }
    else if (strcmp(name, "enablereport") == 0 || strcmp(name, "en_rpt") == 0)
    {
        ret = EN_REPORT;
    }
    else
    {
        ret = UNKNOWN;
    }

    return ret;
}

int get_fw_path_from_input(char *buf)
{
    char *substr = NULL;
    int len = 0;
    int path_format = PATH;
    substr = strtok(buf, CMD_DELIN);
    do
    {
        ILI_DBG("substr = %s\n", substr);
        if (len == 0)
        {
            if (strcmp(substr, "path") == 0)
            {
                path_format = PATH;
            }
            else if (strcmp(substr, "inipath") == 0)
            {
                path_format = INI_PATH;
            }
            else if (strcmp(substr, "logpath") == 0)
            {
                path_format = LOG_FILE_PATH;
            }
            else if (strcmp(substr, "data") == 0)
            {
                path_format = INPUT_DATA;
            }
            else if (strcmp(substr, "hidnode") == 0)
            {
                path_format = HID_NODE;
            }
            else if (strcmp(substr, "flag") == 0)
            {
                path_format = FLAG;
            }
            else
            {
                return RET_FAIL_NO;
            }
        }
        else if (len == 1)
        {
            if (path_format == PATH)
            {
                strcpy((char *) ilits.fw_path, substr);
            }
            else if (path_format == INI_PATH)
            {
                strcpy((char *) ilits.ini_path, substr);
            }
            else if (path_format == LOG_FILE_PATH)
            {
                strcpy((char *) ilits.save_path, substr);
            }
            else if (path_format == INPUT_DATA)
            {
                strcpy((char *) ilits.data, substr);
            }
            else if (path_format == HID_NODE)
            {
                strcpy((char *) ilits.hidtestnode, substr);
            }
            else if (path_format == FLAG)
            {
                if (strcmp(substr, "disable") == 0 || strcmp(substr, "0") == 0)
                    ilits.inputflag = DISABLE;
                else
                    ilits.inputflag = ENABLE;
            }
        }
        else
        {
            break;
        }
        len++;
        substr = strtok(NULL, CMD_DELIN);

    } while (substr);
    return 0;
}

void get_input_para(char *para)
{

    // ILI_INFO("check %s\n", para);
    // return change line 
    if (para[0] == 0xD)
    {
        return;
    }

    if (strcmp(para, "log") == 0)
    {
        debug_log_en = ENABLE;
        log_en = ENABLE;
    }
    else if (strcmp(para, "fail") == 0)
    {
        debug_ret = RET_FAIL;
    }
    else
    {
        if (get_fw_path_from_input(para) < 0)
        {
            printf("unknown : [%s]\n", para);
        }
    }
}

void ili_wr_tp_reg(u8 *cmd, u8 casenum)
{
    u32 rw_reg[6] = {0};
    u32 count = 0;
    u32 addr, read_data, write_data, len;
    char *token = NULL, *cur = NULL;
    ILI_INFO("%s\n", cmd);
    token = cur = (char *) cmd;
    while ((token = strsep(&cur, ",")) != NULL)
    {
        if (count >= (sizeof(rw_reg) / sizeof(u32)))
        {
            ILI_ERR("command length is larger than function need\n");
            break;
        }
        rw_reg[count] = ili_str2hex(token);
        ILI_INFO("rw_reg[%d] = 0x%x\n", (int) count, rw_reg[count]);
        count++;
    }

    addr = rw_reg[0];
	len = rw_reg[1];
    if (ilits.inputflag)
        ili_ic_hid_report_ctrl(DISABLE);

    if (casenum == WRITE)
    {
	    write_data = rw_reg[2];
        ili_ice_mode_write(addr, write_data, len);
        printf("tp reg write addr=0x%08X, write_data = 0x%08X,, len = %d\n", addr, write_data, (int) len);
    } 
    else
    {
        ili_ice_mode_read(addr, &read_data, len);
        printf("tp reg read addr=0x%08X, read_data = 0x%08X,, len = %d\n", addr, read_data, (int) len);
    }
    if (ilits.inputflag)
        ili_ic_hid_report_ctrl(ENABLE);
}

void ili_wr_ddi_reg(u8 *cmd, u8 casenum)
{
    u8 rw_reg[6] = {0};
    u8 count = 0;
    u8 page, ddi_reg, data, paraCnt,msmode = UNKNOWN_MODE;
    char *token = NULL, *cur = NULL;
    ILI_DBG("input[%s]\n", cmd);
    token = cur = (char *) cmd;
    while ((token = strsep(&cur, ",")) != NULL)
    {
        if (count >= (sizeof(rw_reg) / sizeof(u8)))
        {
            ILI_ERR("command length is larger than function need\n");
            break;
        }
        if (count == 0)
        {
            if (strcmp(token, "master") == 0 || strcmp(token, "Master") == 0 ||
                strcmp(token, "MASTER") == 0)
            {
                msmode = MASTER;
            }
            else if (strcmp(token, "slave") == 0 || strcmp(token, "Slave") == 0 ||
                strcmp(token, "SLAVE") == 0)
            {
                msmode = SLAVE;
            }
            else
            {
                msmode = UNKNOWN_MODE;
            }
        }
        else
        {
            rw_reg[count] = (u8) (ili_str2hex(token) & 0xFF);
            ILI_DBG("rw_reg[%d] = 0x%x\n", (int) count, rw_reg[count]);
        }

        count++;
    }

    if (ilits.inputflag)
        ili_ic_hid_report_ctrl(DISABLE);

    if (msmode == UNKNOWN_MODE)
    {
        ILI_INFO("DDI register is unknown mode\n");
        return;
    }
    page = rw_reg[1];
    ddi_reg = rw_reg[2];
    if (casenum == WRITE)
    {
	    data = rw_reg[3];
        ili_ddi_reg_write(page, ddi_reg, data, msmode);
    }
    else
    {
        paraCnt = rw_reg[3];
        ili_ddi_reg_read(page, ddi_reg, paraCnt, msmode);
    }

    if (ilits.inputflag)
        ili_ic_hid_report_ctrl(ENABLE);
}

bool isTDDI(void)
{
    bool ret = false;
    u8 key[16] = {0};
#if CPLUS_COMPILER
    ilitsmp = (ilitek_ts_data_mp*) malloc(sizeof(struct ilitek_ts_data_mp) * sizeof(u8));
#else
    ilitsmp = malloc(sizeof(struct ilitek_ts_data_mp) * sizeof(u8));
#endif
    ili_ic_init();
    ili_ic_get_info();
    ili_ic_get_protocl_ver();
    snprintf((char *) &key, sizeof(key), "%04X%04X", ilits.chip.id, ilits.chip.potocal_ver >> 8);
    ILI_INFO("key = %s\n", key);

    if ((strcmp((const char *) key, "98820506") == 0) || (strcmp((const char *) key, "98820507") == 0))
    {
        ret = true;
    }
    ipio_free((void **)&ilitsmp);
    return ret;
}

int main(int argc, char **argv)
{
    int res, i, retry;
    int ret = 0;
    struct hidraw_devinfo info;

    ILI_DBG("argc = %d\n", argc);
    init_hid();

    if (argv[1] == NULL)
    {
        printf("unknown\n");
        return RET_FAIL;
    }
    else
    {
        removeCR(argv[1]);
        testcase = get_test_case(argv[1]);

        i = 2;
        while (i < 10)
        {
            if (argv[i] != NULL)
            {
                removeCR(argv[i]);
                get_input_para(argv[i]);
            }
            else
            {
                break;
            }
            i++;
        }
    }

    if (open_hidraw_device() < 0)
    {
        ILI_INFO("open %s node error.\n", ilits.hidnode);
        return RET_FAIL;
    }

    switch (testcase)
    {
    case FW_UPGRADE:
        ILI_INFO("ILITEK HID TOOL VERSION = %s\n", HID_DAEMON_VERSION);
        ILI_INFO("FW path = %s\n", ilits.fw_path);
        retry = FW_UPGRADE_RETRY;
        do
        {
            if (open_hex((char *) &ilits.fw_path) < 0)
            {
                ILI_ERR("error file : %s\n", ilits.fw_path);
                break;
            }
            ILI_INFO("-------------------------------------------------\n");
            res = do_fw_upgrade();
            if (res == UPDATE_PASS)
            {
                break;
            }
            else
            {
                if (retry > 1)
                {
                    ILI_ERR("update FW fail retry it.\n");
                    msleep(RETRY_UPGRADE_T);
                }
            }
        } while (--retry > 0);

        if (res == UPDATE_PASS)
        {
            printf("Upgrade firmware = PASS\n");
            ret = RET_PASS;
        }
        else
        {
            ili_ic_get_pc_counter();
            printf("Upgrade firmware = FAIL\n");
            ret = RET_FAIL;
        }
        break;
    case CHECK_CRC:
        if (ilits.inputflag)
            ili_ic_hid_report_ctrl(DISABLE);

        printf("fw-crc-tag: [%s]\n", (check_fw_crc((char *) &ilits.fw_path[0]) == UPDATE_PASS) ? "CRC_PASS" : "CRC_FAIL");

        if (ilits.inputflag)
            ili_ic_hid_report_ctrl(ENABLE);
        break;
    case MP_LCM_ON:
        ILI_INFO("ILITEK HID TOOL VERSION = %s\n", HID_DAEMON_VERSION);
        res = ili_mp_test((u8 *) &ilits.ini_path[0], (u8 *) &ilits.save_path[0]);
        res = (res == MP_TEST_PASS) ? RET_PASS : RET_FAIL;
        break;
    case RESET:
        ILI_INFO("reset ic\n");
        ili_ic_whole_reset(ON);
        break;
    case FWVER:
        if (ilits.inputflag)
            ili_ic_hid_report_ctrl(DISABLE);
        ili_ic_get_fw_ver(false);
        printf("fw-version-tag: [%02X.%02X.%02X.%02X]\n", ilits.chip.fw_ver_buf[3], ilits.chip.fw_ver_buf[2]
            , ilits.chip.fw_ver_buf[1], ilits.chip.fw_ver_buf[0]);
        if (ilits.inputflag)
            ili_ic_hid_report_ctrl(ENABLE);
        break;
    case CK_BL:
        if (ilits.inputflag)
            ili_ic_hid_report_ctrl(DISABLE);
        printf("fw-mode-tag: [%s]\n", (is_in_bootloader_mode()) ? "BL" : "NON_BL");
        if (ilits.inputflag)
            ili_ic_hid_report_ctrl(ENABLE);
        break;
    case ISTDDI:
        if (ilits.inputflag)
            ili_ic_hid_report_ctrl(DISABLE);

        printf("fw-tddi-tag: [%s]\n", (isTDDI()) ? "TDDI" : "NON_TDDI");

        if (ilits.inputflag)
            ili_ic_hid_report_ctrl(ENABLE);
        break;
    case DAEMON_VER:
        printf("ILITEK HID TOOL VERSION = %s\n", HID_DAEMON_VERSION);
        break;
    case VER_INFO:
        if (ilits.inputflag)
            ili_ic_hid_report_ctrl(DISABLE);
        ili_ic_get_info();
        ili_ic_get_fw_ver(true);
        ili_ic_get_core_ver();
        ili_ic_get_protocl_ver();
        if (ilits.inputflag)
            ili_ic_hid_report_ctrl(ENABLE);
        break;
    case WRITE_TP_REG:
        ili_wr_tp_reg(ilits.data, WRITE);
        break;
    case READ_TP_REG:
        ili_wr_tp_reg(ilits.data, READ);
        break;
    case WRITE_DDI_REG:
        ili_wr_ddi_reg(ilits.data, WRITE);
        break;
    case READ_DDI_REG:
        ili_wr_ddi_reg(ilits.data, READ);
        break;
    case SWITCH_AP_MODE:
        ili_hid_switch_tp_mode(P5_X_FW_AP_MODE);
        break;
    case SWITCH_MP_MODE:
        ili_hid_switch_tp_mode(P5_X_FW_TEST_MODE);
        break;
    case SWITCH_BL_MODE:
        switch_bootloader();
        break;
    case HID_INFO:
        memset(&info, 0x0, sizeof(info));
         if (open_hid_node() < 0)
        {
            ILI_INFO("open %s node error.\n", ilits.hidnode);
            return RET_FAIL;
        }
        res = ioctl(ilits.fd_hidraw, HIDIOCGRAWINFO, &info);
        if (res < 0) {
            perror("HIDIOCGRAWINFO");
        } else {
            printf("Raw Info:\n");
            printf("\tvendor: 0x%04hx\n", info.vendor);
            printf("\tproduct: 0x%04hx\n", info.product);
        }
        break;
    case DIS_REPORT:
        printf("Disable report\n");
        ili_ic_hid_report_ctrl(DISABLE);
        break;
    case EN_REPORT:
        printf("Enable report\n");
        ili_ic_hid_report_ctrl(ENABLE);
        break;
    default:
        printf("UNKNOWN CASE!\n");
        break;
    }
    close_hid_node();
    /* for script test fail case */
    if (debug_ret == RET_FAIL)
        ret = RET_FAIL;

    return ret;
}