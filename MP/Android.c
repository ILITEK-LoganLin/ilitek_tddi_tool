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
#include "../hidi2c.h"

void releaseDevice(void)
{
	ILI_INFO("Call releaseDevice() API\n");

    ili_mp_test_free();
	ili_ic_free();
}

int loadConfig(char *strPath)
{
	ILI_INFO("Call loadConfig() API\n");

	char* ini_path;
	int ret = -1;

	ini_path = strPath;

	ILI_INFO("path = %s\n", ini_path);
	if (ini_path == NULL)
	{
		ILI_ERR("Ini path is null\n");
		ret = MP_LOAD_MP_INI_FAIL;
		goto out; /* OutOfMemoryError already thrown */
	}

	ret = ili_mp_ini_parser(ini_path);
	if (ret < 0)
	{
		ILI_ERR("Load mp.ini fail\n");
		ret = MP_LOAD_MP_INI_FAIL;
		goto out;
	}

out:
	return ret;
}

bool createReport(char *strDir, char *strName)
{
	ILI_INFO("Call createReport() API\n");

	const char *csv_path, *csv_name;
	char csv_full_path[256];
	char time_buffer[26];
	time_t timer;
	struct tm* tm_info;
	bool ret = true;

	memset(csv_full_path, '\0', sizeof(csv_full_path));

	csv_path = strDir;
	csv_name = strName;

	ILI_INFO("Get csv path and csv name from parameters\n");

	if (csv_path == NULL || csv_name == NULL)
	{
		ILI_ERR("csv path and csv name is null\n");
		ret = false; /* OutOfMemoryError already thrown */
		goto out;
	}

	memcpy(ilitsmp->u8CsvPath, csv_path, strlen(csv_path) + 1);

	if (strcmp(csv_name, "") == 0)
	{
		time(&timer);
		tm_info = localtime(&timer);
		strftime(time_buffer, 16, "%Y%m%d%H%M%S", tm_info);
		sprintf((char*)ilitsmp->u8CsvFileName, "result_%s", time_buffer);
	}
	else
	{
		memcpy(ilitsmp->u8CsvFileName, csv_name, strlen(csv_name) + 1);
	}

	sprintf(csv_full_path, "%s%s.csv", ilitsmp->u8CsvPath, ilitsmp->u8CsvFileName);
	ILI_INFO("Create CSV point in [%s]\n", csv_full_path);

	if ((ilitsmp->csv_fp = open(csv_full_path, O_WRONLY | O_CREAT, 0700)) == -1)
	{
		ILI_ERR("Create csv point fail!, error no = %s\n", strerror(errno));
		ret = false;
		goto out;
	}

out:

	return ret;
}

void closeReport(void)
{
	ILI_INFO("Call closeReport() API\n");

	close(ilitsmp->csv_fp);
	ilitsmp->csv_fp = 0;
}

int startMPTest(bool lcm_on)
{
	ILI_INFO("startMPTest,run LCM %s\n", lcm_on ? "ON" : "OFF");
	int ret = MP_TEST_NONE;
	char result[100] = {0};
	int i = 0;

	/* Running MP Test */
	ret = ili_mp_test_main(lcm_on);

	ILI_INFO("MP Test ret = %d\n", ret);

	//init result array
    for(i = 0; i< (int) ARRAY_SIZE(result);i++)
    {
        result[i] = MP_ITEM_NA;
    }

	/* copy MP result to callback funtion */
	ili_mp_copy_result(result, ARRAY_SIZE(result));

	ILI_INFO("startMPTest end\n");

	return ret;
}