J-Link Firmware Extractor
=========================

## 使用说明

1. 将Jlink的安装包用7zip解压.
2. 将extractor放入解压后的目录.
3. 执行extractor, 默认将提取全部可用固件.

## 可选命令行选项

- `-l`：仅列出固件, 不进行提取.
- `"model name"`: 提取特定固件.

## 编译方法

本项目可使用 Windows Driver Kit (WDK), VC, GCC进行编译.

1. 安装 WDK 7.1.
2. 打开 Windows XP X86 Free 命令提示符.
3. 使用 `cd /D` 命令进入项目目录.
4. 运行 `build` 命令.

## 注意事项

- 程序需要 JLinkARM.dll 在同一目录下.
- v7.x以后的软件包, 需要 Firmwares 目录才能解压标记为 file 来源的固件.
- 提取的固件将保存在 out 目录中.

## Usage

1. Use 7-Zip to extract the J-Link installation package.
2. Place the extractor executable in the extracted directory.
3. Run the extractor. The default action is extract all firmware.

## Optional Command Line Options

- `-l`: List firmware only, without extracting.
- `"model name"`: Extract specific firmware.

## Compilation

This project uses Windows Driver Kit (WDK) for compilation. Here's how to build it:

1. Install WDK 7.1.
2. Open a WDK command prompt for Windows XP X86 Free build.
3. Use `cd /D` to navigate to the project directory in the command prompt.
4. Run `build` command.

## Notes

- The program requires JLinkARM.dll to be present in the same directory.
- For software packages after v7.x, some firmware sources are inside the "Firmwares" folder.
- Extracted firmware will be saved in the "out" directory.