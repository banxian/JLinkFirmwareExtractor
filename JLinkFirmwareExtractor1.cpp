#include <Windows.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <direct.h>
#include <conio.h>
#include <sys/stat.h>
#include <io.h>
#include <fcntl.h>
#include <time.h>
#include "jlinkfirmware.h"


void quickdump(unsigned int addr, const unsigned char *data, unsigned int amount);
void setwin32filetime(const char* path, tm time);
int errprintf(__in_z __format_string const char * _Format, ...);

uintptr_t func_getfw_full = 0;
void (__cdecl *func_dbgfree)(void* buffer) = 0;
int (__cdecl *COMPRESS_DecompressToMem)(const firmware_decinfo_s*, void *, uint32_t, void *, uint32_t, uint32_t, void*);
int (__cdecl *func_decodefile)(const void *, size_t, void *, size_t);
void fastlz_level1_decompress(const uint8_t* input, int length, uint8_t* output);
int _cdecl _decodefile(const uint8_t *src, size_t srclen, uint8_t *dest, size_t destlen);


void xordecode(void* dst, const void* src, size_t len);
void normalizefilename(char* filepath);
tm get_build_date(const char* version);

int main(int argc, char* argv[])
{
    bool listonly = false;
    const char* fwid = NULL;
    bool matchall = true;
    for (int i = 1; i < argc; i++) {
        if (strlen(argv[i])) {
            if (_stricmp(argv[i], "-L") == 0) {
                listonly = true;
                continue;
            }
            fwid = argv[i];
            if (strcmp(fwid, "*")) {
                matchall = false;
            }
        }
    }
    HMODULE dllmodule = LoadLibraryA("JLinkARM.dll");
    if (dllmodule == NULL) {
        errprintf("LoadLibarary Failed!\n");
        return 0;
    }

    PIMAGE_DOS_HEADER dosheader = (PIMAGE_DOS_HEADER)dllmodule;
    PIMAGE_NT_HEADERS ntheader = (PIMAGE_NT_HEADERS)((DWORD)dosheader + dosheader->e_lfanew);
    PIMAGE_SECTION_HEADER sechdrs = (PIMAGE_SECTION_HEADER)(ntheader + 1);
    //printf("SizeOfCode: %08X, SizeOfImage: %08X\n", ntheader->OptionalHeader.SizeOfCode, ntheader->OptionalHeader.SizeOfImage);
    uint8_t* databegin = (uint8_t*)dllmodule + ntheader->OptionalHeader.BaseOfData; // TODO: bypass .idata
    uint8_t* dataend = databegin + ntheader->OptionalHeader.SizeOfInitializedData + ntheader->OptionalHeader.SizeOfUninitializedData;
    uint8_t* codebegin = (uint8_t*)dllmodule + ntheader->OptionalHeader.BaseOfCode;
    uint8_t* codeend = codebegin + ntheader->OptionalHeader.SizeOfCode;
    //quickdump(ntheader->OptionalHeader.BaseOfData, (unsigned char*)databegin, 0x100);
    bool hitted = false;
    firmware_rec_s* g_fwarray = NULL;
    uint32_t arraysize;
    uint32_t itemsize;
    // 寻找"J-Trace ARM Rev.1"
    for (uint8_t* strpat = databegin; strpat < dataend - sizeof("J-Trace ARM Rev.1") && !hitted; strpat++) {
        if (*(uint32_t*)strpat == 'rT-J' && memcmp(strpat, "J-Trace ARM Rev.1", sizeof("J-Trace ARM Rev.1")) == 0) {
            printf("Found \"J-Trace ARM Rev.1\" at RVA 0x%08X\n", strpat - (uint8_t*)dllmodule);
            for (uint8_t* lpstrpat = databegin; lpstrpat < dataend - sizeof(lpstrpat) && !hitted; lpstrpat++) {
                if (*(uint32_t*)lpstrpat == (uint32_t)strpat) {
                    printf("Found g_fwarray at RVA 0x%08X\n", lpstrpat - (uint8_t*)dllmodule);
                    // .text:100B6CD6 BF A8 3A 42 10                       mov     edi, offset g_fwarray
                    for (uint8_t* movedi = codebegin; movedi < codeend - 0x20 && !hitted; movedi++) {
                        if (*movedi == 0xBF && *(uint32_t*)(movedi + 1) == (uint32_t)lpstrpat) {
                            printf("Found \"mov edi, offset g_fwarray\" at RVA 0x%08X\n", movedi - (uint8_t*)dllmodule);
                            //.text:100B6D3B 83 C7 4C                             add     edi, 4Ch
                            //.text:100B6D3E 81 FD 3C 19 00 00                    cmp     ebp, 193Ch
                            //.text:100B6D44 72 9A                                jb      short loc_100B6CE0

                            //.text:100AF60F 83 C7 48                             add     edi, 48h ; 'H'
                            //.text:100AF612 81 FB 60 15 00 00                    cmp     ebx, 1560h
                            //.text:100AF618 72 99                                jb      short loc_100AF5B3
                            // 最好寻找函数结束再往回搜
                            for (uint8_t* cmpebp = movedi; cmpebp < movedi + 0x200; cmpebp++) {
                                if ((*(uint16_t*)cmpebp & 0xF0FF) == 0xF081 && *(cmpebp + 6) == 0x72 && (*(cmpebp - 1) == 0x4C || *(cmpebp - 1) == 0x48)) {
                                    arraysize = *(uint32_t*)(cmpebp + 2);
                                    itemsize = *(cmpebp - 1);
                                    g_fwarray = (firmware_rec_s*)lpstrpat;
                                    printf("Found \"cmp exx, %Xh\" at RVA 0x%08X\n", arraysize, cmpebp - (uint8_t*)dllmodule);
                                    hitted = true;
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    // "EMU_Firmware: FW image"
    // "Decompressing FW took %d us"
    // "DEFLATE"
    if (!listonly) {
        for (uint8_t* strpat = databegin; strpat < dataend - sizeof("DEFLATE") && !COMPRESS_DecompressToMem; strpat++) {
            if (*(uint32_t*)strpat == 'LFED' && memcmp(strpat, "DEFLATE", sizeof("DEFLATE")) == 0) {
                printf("Found \"DEFLATE\" at RVA 0x%08X\n", strpat - (uint8_t*)dllmodule);
                //.text:10177139 68 3C 51 67 10                       push    offset aDeflate
                for (uint8_t* pushpat = codebegin; pushpat < codeend - 0x20 && !COMPRESS_DecompressToMem; pushpat++) {
                    if (*pushpat == 0x68 && *(uint32_t*)(pushpat + 1) == (uint32_t)strpat) {
                        // 本函数是DEFLATE_CopyName, 寻找上一个函数入口
                        //.text:101770E0 8B 44 24 0C                          mov     eax, [esp+wrkmemsize]
                        //.text:101770E4 8B 4C 24 08                          mov     ecx, [esp+wrkmem]
                        //.text:101770E8 83 EC 18                             sub     esp, 18h
                        for (uint8_t* prolog = pushpat; prolog >= pushpat - 0x100; prolog--) {
                            if (*(uint32_t*)prolog == 0x0C24448B && *(uint32_t*)(prolog + 4) == 0x08244C8B) {
                                printf("Found function DecompressToMem at RVA 0x%08X\n", prolog - (uint8_t*)dllmodule);
                                *(uintptr_t*)&COMPRESS_DecompressToMem = (uintptr_t)prolog;
                                break;
                            }
                        }
                    }
                }
            }
        }
        //.text:100B7276 05 00 02 00 00                       add     eax, 200h
        //.text:100B727B 50                                   push    eax             ; src
        //.text:100B727C E8 1F FF F5 FF                       call    j_func_decodefile
        for(uint8_t* addeax = codebegin; addeax < codeend - 0x20 && !func_decodefile; addeax++) {
            if (*(uint32_t*)addeax == 0x00020005 && *(uint16_t*)(addeax + 4) == 0x5000) {
                for (uint8_t* calldecode = addeax + 6; calldecode < addeax + 0x20; calldecode++) {
                    if (*calldecode == 0xE8) {
                        uint8_t* calldest = calldecode + *(uint32_t*)(calldecode + 1) + 5;
                        if (calldest >= codebegin && calldest < codeend) {
                            printf("Found function decodefile at RVA 0x%08X\n", calldest - (uint8_t*)dllmodule);
                            *(uintptr_t*)&func_decodefile = (uintptr_t)calldest;
                            break;
                        }
                    }
                }
            }
        }
    }
    // 判断是7.22还是v6版长度
    firmware_rec_s* fwrec7 = g_fwarray;
    firmware6_rec_s* fwrec6 = (firmware6_rec_s*)g_fwarray;
    if (hitted) {
        int localfiles = 0, saved = 0;
        for (size_t i = 0; i < arraysize / itemsize; i++, fwrec7++, fwrec6++) {
            // 统一到7的存储
            firmware_rec_s via;
            firmware_rec_s* fwrec = (itemsize == 0x4C)?fwrec7:&via;
            if (itemsize != 0x4C) {
                via.displayname = fwrec6->displayname;
                via.localfile = 0;
                memcpy(&via.body, &fwrec6->body, 0x44);
            }
            // 数组最后有一个空白记录
            if (fwrec->displayname == 0) {
                break;
            }
            if (fwrec->decinfo) {
                printf("%d %X dec %X", i + 1, fwrec->decinfo->fwlen, fwrec->decinfo->decompresslen);
            } else {
                printf("%d %X", i + 1, fwrec->len);
            }
            printf(" flash %X %s", fwrec->flashspace, fwrec->displayname);
            if (fwrec->localfile) {
                printf(" (%s)", fwrec->localfile);
                localfiles++;
            }
            printf("\n");
#ifdef _DEBUG
            /*if (fwrec->decinfo) {
                //printf("functions: %08X\n", fwrec->decinfo->functions);
                void(__cdecl*_CopyName)(char*, size_t) = *(void(__cdecl**)(char*, size_t))fwrec->decinfo->functions;
                char algname[16];
                _CopyName(algname, sizeof(algname) - 1);
                printf("Method: %s\n", algname);
            }*/
#endif
            if (!listonly && COMPRESS_DecompressToMem) {
                char* displayname = _strdup(fwrec->displayname);
                char* lptail = &displayname[strlen(displayname) - 1];
                while (*lptail == ' ') {
                    *lptail-- = 0;
                }
                if (matchall || _stricmp(fwid, displayname) == 0) {
                    _mkdir("out");
                    bool isrev5 = _stricmp(displayname, "Rev.5") == 0 && fwrec->dispnamepos == 41;
                    bool localname = !fwrec->decinfo && fwrec->localfile;
                    // TODO: alternative displayname to localfile if no decinfo and have localfile
                    size_t namelen = localname?strlen(fwrec->localfile):isrev5?strlen("J-Link ARM Rev.5"):strlen(displayname);
                    char* filename = (char*)malloc(namelen + 28);
                    strcpy(filename, "out\\");
                    if (localname) {
                        if (const char* dot = strrchr(fwrec->localfile, '.')) {
                            strncat(filename, fwrec->localfile, dot - fwrec->localfile);
                        } else {
                            strcat(filename, fwrec->localfile);
                        }
                    } else {
                        normalizefilename(displayname);
                        // Rev.5
                        // J-Link compiled Jul 30 2008 11:24:37 ARM Rev.5
                        strcat(filename, isrev5?"J-Link ARM Rev.5":displayname);
                    }
                    bool dualout = false;
                    void* fwbuffer = 0, *fwbuffer2 = 0;
                    uint32_t fwsize = 0, fwsize2 = 0;
                    if (fwrec->decinfo && fwrec->decinfo->decompresslen && fwrec->decinfo->fwbody && fwrec->decinfo->fwlen) {
                        fwbuffer = malloc(fwrec->decinfo->decompresslen);
                        fwsize = fwrec->decinfo->decompresslen;
                        void* wrkmem = malloc(fwrec->decinfo->workmemlen * 2);
                        //COMPRESS_DecompressToMem(fwrec->decinfo, wrkmem, 2 * fwrec->decinfo->workmemlen, fwimage, 0, fwrec->decinfo->decompresslen - 1, 0);
                        int err = COMPRESS_DecompressToMem(fwrec->decinfo, wrkmem, 2 * fwrec->decinfo->workmemlen, fwbuffer, 0, fwrec->decinfo->decompresslen, 0);
                        if (err < 0) {
                            errprintf("Decode failed %d!\n", err);
                        } else {
                            fwsize = err;
                        }
                        free(wrkmem);
                    }
                    // usexor 只处理无压缩存储(无论是内嵌数据还是文件数据)
                    if (!fwrec->decinfo) {
                        // TODO: localfile
                        if (fwrec->localfile) {
                            char* fwpath = (char*)malloc(strlen(fwrec->localfile) + sizeof("Firmwares\\"));
                            strcpy(fwpath, "Firmwares");
                            struct _stat st;
                            if (_stat(fwpath, &st) == -1 || (st.st_mode & S_IFMT) != S_IFDIR) {
                                errprintf("Missing \"Firmwares\" directory in current folder!\nDid you forgot cd to j-link folder?\n");
                            }
                            strcat(fwpath, "\\");
                            strcat(fwpath, fwrec->localfile);
                            if (_stat(fwpath, &st) == -1) {
                                errprintf("File \"%s\" was missing!\n", fwpath);
                            } else {
                                char* filebuffer = (char*)malloc(st.st_size);
                                int fd = _open(fwpath, O_RDONLY | O_BINARY);
                                _read(fd, filebuffer, st.st_size);
                                int filetype = filebuffer[0x80];
                                size_t dstlen = *(uint32_t*)(filebuffer + 0x84);
                                fwsize = fwrec->flashspace?fwrec->flashspace:dstlen;
                                fwbuffer = (char*)malloc(fwsize);
                                if (filetype == 1) {
                                    int decoded = func_decodefile?
                                                  func_decodefile(filebuffer + 0x200, st.st_size - 0x200, fwbuffer, dstlen):
                                                  _decodefile((uint8_t*)filebuffer + 0x200, st.st_size - 0x200, (uint8_t*)fwbuffer, dstlen);
                                    if (decoded != dstlen) {
                                        errprintf("decode file failed: %d\n", decoded);
                                    } else {
                                        fwsize = dstlen;
                                    }
                                    //fastlz_level1_decompress((uint8_t*)filebuffer + 0x200, st.st_size - 0x200, (uint8_t*)fwbuffer);
                                }
                                if (filetype == 0) {
                                    if (fwrec->usexor) {
                                        xordecode(fwbuffer, filebuffer + 0x200, fwsize);
                                    } else {
                                        memcpy(fwbuffer, filebuffer + 0x200, fwsize);
                                    }
                                }
                                free(filebuffer);
                            }
                            free(fwpath);
                        } else {
                            fwsize = fwrec->len;
                            fwsize2 = fwrec->len2;
                            if (fwrec->usexor) {
                                fwbuffer = malloc(fwrec->len);
                                xordecode(fwbuffer, fwrec->body, fwrec->len);
                                if (fwrec->use2) {
                                    fwbuffer2 = malloc(fwrec->len2);
                                    xordecode(fwbuffer, fwrec->body2, fwrec->len2);
                                }
                            } else {
                                fwbuffer = (void*)fwrec->body;
                                if (fwrec->use2) {
                                    fwbuffer2 = (void*)fwrec->body2;
                                }
                            }
                        }
                    }
                    // file1
                    size_t oldfilenamepos = strlen(filename);
                    if (fwbuffer && fwsize) {
                        tm date = get_build_date((char*)fwbuffer + fwrec->timestampoff);
                        sprintf(filename + oldfilenamepos, " %04d %02d %02d", date.tm_year, date.tm_mon, date.tm_mday);
                        FILE* fwfile = fopen(filename, "wb");
                        fwrite(fwbuffer, fwsize, 1, fwfile);
                        fclose(fwfile);
                        setwin32filetime(filename, date);
                        saved++;
                    }
                    // file2
                    if (fwbuffer2 && fwsize2) {
                        tm date = get_build_date((char*)fwbuffer2 + fwrec->timestampoff);
                        // 恢复基础文件名
                        sprintf(filename + oldfilenamepos, "_2 %04d %02d %02d", date.tm_year, date.tm_mon, date.tm_mday);
                        FILE* fwfile = fopen(filename, "wb");
                        fwrite(fwbuffer2, fwsize2, 1, fwfile);
                        fclose(fwfile);
                        setwin32filetime(filename, date);
                        saved++;
                    }
                    if (fwrec->decinfo || fwrec->usexor || fwrec->localfile) {
                        if (fwbuffer) {
                            free(fwbuffer);
                        }
                        if (fwbuffer2) {
                            free(fwbuffer2);
                        }
                    }
                    free(filename);
                }
                free(displayname);
            }
        }
        printf("Saved %d firmware.\n", saved);
        if (itemsize == 0x4C && localfiles) {
            printf("There are %d firmware decode from Firmwares folder.\n", localfiles);
        }
    }

    FreeLibrary(dllmodule);

#ifdef _DEBUG
    _getch();
#endif
	return 0;
}

void xordecode(void* dst, const void* src, size_t len) {
    uint8_t* lpdst = (uint8_t*)dst;
    const uint8_t* lpsrc = (const uint8_t*)src;
    uint8_t xorer = 0xFF;
    while (len--) {
        uint8_t c = *lpsrc++;
        *lpdst++ = c ^ xorer;
        xorer = c ^ 0xA5;
    }
}

void normalizefilename(char* filepath)
{
    size_t len = strlen(filepath);
    while (len--) {
        if (filepath[len - 1] == '\\' || filepath[len - 1] == '/') {
            filepath[len - 1] = '_';
        }
    }
}

tm get_build_date(const char* version)
{
    tm date = {0, };
    // J-Link V9 compiled Oct 25 2018 11:46:07
    // J-Link V10 compiled Feb 21 2019 12:48:07
    // J-Link compiled Jul 30 2008 11:24:37 ARM Rev.5
    // 01234567890123456789
    // Feb 21 2019 12:48:07
    const char* compiled = strstr(version, "compiled ");
    if (compiled == 0) {
        return date;
    }
    compiled += strlen("compiled ");
    date.tm_year = atoi(compiled + 7);
    date.tm_mday = atoi(compiled + 4);
    date.tm_hour = atoi(compiled + 12);
    date.tm_min = atoi(compiled + 15);
    date.tm_sec = atoi(compiled + 18);
    date.tm_mon = 0;
    const char* mon = "JanFebMarAprMayJunJulAugSepOctNovDec";
    for (int i = 0; i < 12; i++, mon += 3) {
        if (_strnicmp(compiled, mon, 3) == 0) {
            date.tm_mon = i + 1;
            break;
        }
    }
    return date;
}

void setwin32filetime(const char* path, tm time)
{
    SYSTEMTIME sys;
    sys.wYear   = (WORD)time.tm_year;
    sys.wMonth  = (WORD)time.tm_mon;
    sys.wDay    = (WORD)time.tm_mday;
    sys.wHour   = (WORD)time.tm_hour;
    sys.wMinute = (WORD)time.tm_min;
    sys.wSecond = (WORD)time.tm_sec;
    // useless
    sys.wDayOfWeek = 0;
    sys.wMilliseconds = 0;
    FILETIME ft;
    if (SystemTimeToFileTime(&sys, &ft)) {
        HANDLE hFile = CreateFileA(path, FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            return;
        }
        SetFileTime(hFile, &ft, &ft, &ft);
        CloseHandle(hFile);
    }
}

int errprintf(__in_z __format_string const char * _Format, ...)
{
    HANDLE hCon = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO info;
    GetConsoleScreenBufferInfo(hCon, &info);
    SetConsoleTextAttribute(hCon, FOREGROUND_RED | FOREGROUND_INTENSITY);
    va_list va;
    va_start(va, _Format);
    int len = vfprintf(stderr, _Format, va);
    va_end(va);
    SetConsoleTextAttribute(hCon, info.wAttributes);

    return len;
}

int _cdecl _decodefile(const uint8_t *src, size_t srclen, uint8_t *dest, size_t destlen)
{
    unsigned int sbase;      // eax
    size_t srclen1;          // edi
    uint32_t headb;          // ebx
    const uint8_t* src1;     // esi
    unsigned int blo3;       // ecx
    uint32_t bhi5;           // ebx
    int bpos;                // edx
    int npos;                // edx
    unsigned int mask15;     // ebx
    int newor;               // eax
    unsigned int idx;        // edi
    unsigned int maskb4;     // ebx
    int bpos0;               // edx
    int maskb3;              // edi
    unsigned int maskbit;    // ecx
    int masked;              // edi
    //char maskb4_a;           // cl
    unsigned int maskb4lo3;  // ecx
    int dpos;                // esi
    int blo3a2_1;            // ecx
    int dposor;              // esi
    int dpos0;               // esi
    uint8_t* lpdest;         // ebp
    uint8_t dstb;            // cl
    uint8_t* ndest;          // esi
    size_t tailen;           // [esp+4h] [ebp-18h]
    int flag33;              // [esp+8h] [ebp-14h]
    //unsigned int sbase;    // [esp+Ch] [ebp-10h]
    unsigned int sb;         // [esp+10h] [ebp-Ch]
    int blo3a2;              // [esp+14h] [ebp-8h]
    //int dpos_a;              // [esp+18h] [ebp-4h]
    const uint8_t* lpsrc;    // [esp+20h] [ebp+4h]
    size_t srclena;          // [esp+24h] [ebp+8h]

    sbase = 0;
    srclen1 = srclen - 1;
    sb = 0;
    srclena = srclen - 1;
    if (!srclen)
        return -101;
    headb = *src;
    src1 = src + 1;
    blo3 = *src & 7;
    lpsrc = src + 1;
    if (blo3 >= 7)
        return -104;
    blo3a2 = blo3 + 2;
    bhi5 = headb >> 3;
    bpos = 5;
    tailen = destlen;
    flag33 = 0;
    dpos = 0;
    while (1) {
        while (1) {
            npos = flag33 + bpos;
            mask15 = (sbase << (char)bpos) | bhi5;
            if (npos <= 32) {
                if (npos >= 32) {
                    flag33 = npos - 32;
                    sbase = sb >> (40 - npos);
                    npos = 32;
                } else {
                    while (srclen1--) {
                        sb = *src1;
                        newor = sb << npos;
                        npos += 8;
                        ++src1;
                        mask15 |= newor;
                        if (npos >= 32) {
                            lpsrc = src1;
                            srclena = srclen1;
                            break;
                        }
                    }
                    if (npos < 31) {
                        lpsrc = src1;
                        srclena = 0;
                        sbase = 0;
                        flag33 = 0;
                        if (npos < 0)
                            return -101;
                    } else {
                        flag33 = npos - 32;
                        sbase = sb >> (40 - npos);
                        npos = 32;
                    }
                }
            } else {
                sbase >>= 6;
                flag33 = 1;
                npos = 32;
            }
            if ((mask15 & 1) != 0)
                break;
            if (!tailen)
                return -100;
            srclen1 = srclena;
            *dest = mask15 >> 1;
            src1 = lpsrc;
            ++dest;
            --tailen;
            bhi5 = mask15 >> 9;
            bpos = npos - 9;
        }
        if ((mask15 & 2) != 0) {
            if ((mask15 & 4) != 0) {
                maskb3 = (mask15 >> 3) & 1;
                maskb4 = mask15 >> 4;
                bpos0 = npos - 4;
            } else {
                maskbit = 1;
                masked = 0;
                while (1) {
                    mask15 >>= 2;
                    npos -= 2;
                    if ((mask15 & 2) != 0)
                        masked += maskbit;
                    maskbit *= 2;
                    if (maskbit >= 0x80)
                        break;
                    if ((mask15 & 4) != 0) {
                        mask15 >>= 1;
                        --npos;
                        break;
                    }
                }
                maskb4 = mask15 >> 2;
                bpos0 = npos - 2;
                maskb3 = maskbit + masked;
            }
            idx = maskb3 + 4;
        } else {
            idx = ((mask15 >> 2) & 1) + 2;
            maskb4 = mask15 >> 3;
            bpos0 = npos - 3;
        }
        // 成功返回
        if (idx > 0x102)
            return destlen - tailen;
        bhi5 = maskb4 >> 3;
        bpos = bpos0 - 3;
        maskb4lo3 = maskb4 & 7;
        if (maskb4lo3) {
            if (maskb4lo3 < 2) {
                blo3a2_1 = blo3a2;
                dposor = 0;
            } else {
                blo3a2_1 = maskb4lo3 + blo3a2 - 2;
                dposor = 1 << blo3a2_1;
            }
            bpos -= blo3a2_1;
            dpos0 = bhi5 & ((1 << blo3a2_1) - 1) | dposor;
            bhi5 >>= blo3a2_1;
            dpos = dpos0 + 1;
        }
        if (idx > tailen)
            return -100;
        lpdest = &dest[-dpos];
        tailen -= idx;
        do {
            dstb = *lpdest;
            ndest = dest++;
            ++lpdest;
            *ndest = dstb;
        } while (--idx);
        src1 = lpsrc;
        srclen1 = srclena;
    }
}