J-Link Firmware Extractor
=========================
使用说明
--------
将Jlink的安装包用7zip解压后, 将extractor放入解压后的目录执行.
v7的新版安装包里带的Firmwares目录不可删除, 有部分固件在此目录加密存放.
命令行参数-l是列表模式, 命令行加产品名称是匹配模式.
解压的文件会放入out目录, 文件日期将设置为固件编译日期.

如何编译
--------
使用WDK的winxp x86环境命令行build.
也可以使用VC和gcc编译.

Usage
-----
Drop extractor exe in to your j-link installation folder and click to run.
Default action is extract all firmware in JLinkARM.dll and Firmwares subfolder.
use -l to list, or use firmware name to extract single firmware.
The extracted files will placed into "out" folder.

Build
-----
use WDK 7600 winxp x86 environment to build.
you can also build in visual studio or gcc.