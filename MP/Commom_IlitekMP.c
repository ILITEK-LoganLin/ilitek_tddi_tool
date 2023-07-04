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
#include "Android.h"
#include "Common.h"
#include "../hidi2c.h"


int createSaveDirPath(u8 *pathname)
{
    mode_t mode = S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IXGRP | S_IROTH | S_IWOTH | S_IXOTH;

    if (mkdir((char *) pathname, mode) == DIR_EXIST)
    {
        ILI_DBG("%s is exist\n", pathname);
    }
    else
    {
        ILI_ERR("Error! %s doesn't exist\n", pathname);
    }

    return 0;
}

void modifyOutputFile(int mpRet, char *filepath)
{
    char tempname[128] = {0};
    char newname[128] = {0};

    time_t rawtime;
	struct tm *timeinfo;

	time(&rawtime);
	timeinfo = localtime(&rawtime);
	sprintf(newname, "%s%04d%02d%02d-%02d%02d%02d_mp_%s.csv",
            filepath,
			(timeinfo->tm_year + 1900), timeinfo->tm_mon, timeinfo->tm_mday,
			timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec,
            (mpRet == MP_TEST_PASS) ? "pass" : "fail");

    sprintf(tempname, "%s%s.csv", filepath, CSV_TEMP);
    rename(tempname, newname);

    printf("\nCSV path:%s\n", newname);
}

int initDevice(void)
{
	ILI_INFO("Call initDevice() API\n");
    int ret = -1;

    if (ili_ic_init() < 0)
	{
		ILI_ERR("Failed to allocate cores' mem\n");
		ret = MP_ALLOCATE_MEM_FAIL;
		goto out;
	}

	if (ili_ic_get_info() < 0)
	{
		ILI_ERR("Chip info is incorrect\n");
		ret = MP_GET_CHIP_ID_FAIL;
		goto out;
	}

    if (ili_ic_get_all_info() < 0) {
        if (ili_ic_get_core_ver() < 0) {
            ILI_ERR("Failed to get core version\n");
            ret = MP_GET_CORE_VERSION_FAIL;
            goto out;
        }

        if (ili_ic_get_protocl_ver() < 0) {
            ILI_ERR("Failed to get protocal version\n");
            ret = MP_GET_PROTOCOL_VERSION_FAIL;
            goto out;
        }

        if (ili_ic_get_fw_ver(true) < 0) {
            ILI_ERR("Failed to get firmware version\n");
            ret = MP_GET_FW_VERSION_FAIL;
            goto out;
        }

        if (ili_ic_get_tp_info() < 0) {
            ILI_ERR("Failed to get TP information\n");
            ret = MP_GET_TP_INFO_FAIL;
            goto out;
        }

        if (ili_ic_get_pen_info() < 0) {
            ILI_ERR("Failed to get pen information\n");
            ret = MP_GET_PEN_INFO_FAIL;
            goto out;
        }

        if (ili_ic_get_panel_info() < 0) {
            ILI_ERR("Failed to get panel information\n");
            ret = MP_GET_PANEL_INFO_FAIL;
            goto out;
        }
    }
out:
	return ret;
}

int ili_mp_test(u8 *ini_path, u8 *save_path)
{
    int ret = MP_TEST_NONE;;

    ILI_INFO("ini path = %s, save path = %s\n", ini_path, save_path);
    if (createSaveDirPath(save_path) < 0) {
        return 0;
    }

    ili_ic_hid_report_ctrl(DISABLE);

    ret = initDevice();

    if (ret != MP_OPEN_CONTROLLER_FAIL && ret != MP_ALLOCATE_MEM_FAIL &&
        ret != MP_HW_RESET_FAIL && ret != MP_GET_CHIP_ID_FAIL &&
        ret != MP_GET_DRIVER_VERSION_FAIL && ret != MP_GET_CORE_VERSION_FAIL &&
        ret != MP_GET_PROTOCOL_VERSION_FAIL && ret != MP_GET_FW_VERSION_FAIL &&
        ret != MP_GET_TP_INFO_FAIL && ret != MP_GET_PANEL_INFO_FAIL)
    {
        ret = loadConfig((char *) ini_path);

        sleep(1);

        if (ret != MP_LOAD_MP_INI_FAIL)
        {
            createReport((char *) save_path, (char *) CSV_TEMP);

            // MP lcm on test
            ret = startMPTest(LCM_ON);

            closeReport();
            if (ret == MP_TEST_PASS)
            {
                ILI_INFO("Final Result = PASS\n");
            }
            else
            {
                ILI_INFO("Final Result = FAIL\n");
            }

            modifyOutputFile(ret, (char *) save_path);
            show_commom_mp_result();
        } else {
            printf("Error! Ilitek MP ini file no exist.\n");
        }
    } else {
        printf("Error! MP FAIL, error code = %d\n", ret);
    }

    ili_ic_hid_report_ctrl(ENABLE);

    releaseDevice();
    return ret;
}