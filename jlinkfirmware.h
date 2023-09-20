#ifndef JLINKFIRMWARE_H
#define JLINKFIRMWARE_H

#include <stdint.h>

struct firmware_decinfo_s
{
    const void *fwbody;
    uint32_t fwlen;
    uint32_t srccrc;
    void *functions;
    uint32_t rev10;
    uint32_t decompresslen;
    uint32_t dstcrc;
    uint32_t workmemlen;
    uint32_t rev20;
    uint32_t rev24;
    uint32_t rev28;
};

// 48
struct firmware6_rec_s
{
    const char *displayname;
    const void *body;
    uint32_t len;
    firmware_decinfo_s *decinfo;
    uint32_t flashspace;
    uint32_t flashlimit;
    uint32_t paddingval;
    uint32_t timestampoff;
    uint32_t dispnamepos;
    uint32_t rev24;
    uint32_t usexor;
    uint32_t rev2C;
    uint32_t rev30;
    uint32_t body2;
    uint32_t len2;
    uint32_t use2;
    uint32_t rev40;
    uint32_t rev44;
};

// 4C
struct firmware722_rec_s
{
    const char *displayname;
    const char *localfile;
    const void *body;
    uint32_t len;
    firmware_decinfo_s *decinfo;
    uint32_t flashspace;    // 填充到此长度
    uint32_t flashlimit;    // 能放的有效长度
    uint32_t paddingval;    // 填充内值
    uint32_t timestampoff;  // 固件版本信息偏移
    uint32_t dispnamepos;   // 产品名匹配位置(有些版本品名会变)
    uint32_t rev28;
    uint32_t usexor;        // 使用简易XOR
    uint32_t rev30;
    uint32_t rev34;
    const void* body2;      // 备用固件内容
    uint32_t len2;          // 备用固件长度
    uint32_t use2;          // 双固件判断程序
    uint32_t rev44;
    uint32_t rev48;
};

// 58
struct firmware_rec_s : firmware722_rec_s
{
    uint32_t rev4C;
    uint32_t rev50;
    bool pub54;
    char pad55[3];
};

#endif