# ilitek_tddi tool
**Linux TDDI tool for ChromeOS touch firmware update**

**This is a firmware update tool for ILITEK touch controller**

**Compilation**
Just type 'make' on the root directory os this projecct
    $ make

**How to perform a Firmware Update:**
  1. Put ILITEK firmware update tool "ilitek_tddi" into target system (executable path ex. /usr/local/.)
  2. Check *.hex firmware is ready and accessible in the target system.
  3. key-in command as below, please check and replace each command argument with the following description.

    ```
	ilitek_tddi FWUpgrade path=<.hex file path>
	 <.hex file path>  replace with your .hex file path

	```