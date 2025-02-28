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
#include "ldisasm.h"


void quickdump(unsigned int addr, const unsigned char *data, unsigned int amount);
void setwin32filetime(const char* path, tm time);
int colorprintf(WORD color, __in_z __format_string const char * _Format, ...);
#define errprintf(fmt, ...) colorprintf(FOREGROUND_RED | FOREGROUND_INTENSITY, fmt, ##__VA_ARGS__)
void printfound(const char* name, unsigned int addr);

uintptr_t func_getfw_full = 0;
void (__cdecl *func_dbgfree)(void* buffer) = 0;
int (__cdecl *COMPRESS_DecompressToMem)(const firmware_decinfo_s*, void *, uint32_t, void *, uint32_t, uint32_t, void*);
int (__cdecl *func_decodefile)(const void *, size_t, void *, size_t);
void fastlz_level1_decompress(const uint8_t* input, int length, uint8_t* output);
int _cdecl _decodefile(const uint8_t *src, size_t srclen, uint8_t *dest, size_t destlen);


void xordecode(void* dst, const void* src, size_t len);
void normalizefilename(char* filepath);
tm get_build_date(const char* version);
uint32_t parseitemsize(uint8_t* codeptr, int limit);

typedef struct {
    WORD wLength;
    WORD wValueLength;
    WORD wType;
    WCHAR szKey[16]; // "VS_VERSION_INFO\0"
    WORD Padding1;
    VS_FIXEDFILEINFO Value;
    WORD Padding2;
    WORD Children;
} VS_VERSIONINFO;

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
    // TODO: search path
#ifdef _DEBUG
    char fullPath[MAX_PATH];
    GetFullPathNameA("JLinkARM.dll", _countof(fullPath), fullPath, NULL);
    HMODULE dllmodule = LoadLibraryA(fullPath);
#else
    HMODULE dllmodule = LoadLibraryA("JLinkARM.dll");
#endif
    if (dllmodule == NULL) {
        errprintf("LoadLibarary Failed!\n");
        return 0;
    }
    HRSRC hResInfo = FindResource(dllmodule, MAKEINTRESOURCE(VS_VERSION_INFO), RT_VERSION);
    HGLOBAL hResData = LoadResource(dllmodule, hResInfo);
    VS_VERSIONINFO* info = (VS_VERSIONINFO*)LockResource(hResData);
    int aver = info->Value.dwFileVersionLS >> 16;
    printf("DLL version: %d.%d", info->Value.dwFileVersionMS >> 16, (WORD)info->Value.dwFileVersionMS);
    if (aver) {
        putchar('a'+aver-1);
    }
    putchar('\n');
    FreeResource(hResData);
    UnlockResource(info);

    PIMAGE_DOS_HEADER dosheader = (PIMAGE_DOS_HEADER)dllmodule;
    PIMAGE_NT_HEADERS ntheader = (PIMAGE_NT_HEADERS)((DWORD)dosheader + dosheader->e_lfanew);
    PIMAGE_SECTION_HEADER sechdrs = (PIMAGE_SECTION_HEADER)(ntheader + 1);
    //printf("SizeOfCode: %08X, SizeOfImage: %08X\n", ntheader->OptionalHeader.SizeOfCode, ntheader->OptionalHeader.SizeOfImage);
    uint8_t* databegin = (uint8_t*)dllmodule + ntheader->OptionalHeader.BaseOfData; // TODO: bypass .idata
    uint8_t* dataend = databegin + ntheader->OptionalHeader.SizeOfInitializedData + ntheader->OptionalHeader.SizeOfUninitializedData;
    uint8_t* codebegin = (uint8_t*)dllmodule + ntheader->OptionalHeader.BaseOfCode;
    uint8_t* codeend = codebegin + ntheader->OptionalHeader.SizeOfCode;
    //quickdump(ntheader->OptionalHeader.BaseOfData, (unsigned char*)databegin, 0x100);
    bool found = false;
    firmware_rec_s* g_fwarray = NULL;
    uint32_t itemsize, itemcount = 0;
    // 寻找"J-Trace ARM Rev.1"
    for (uint8_t* strpat = databegin; strpat < dataend - sizeof("J-Trace ARM Rev.1") && !found; strpat++) {
        if (*(uint32_t*)strpat == 'rT-J' && memcmp(strpat, "J-Trace ARM Rev.1", sizeof("J-Trace ARM Rev.1")) == 0) {
            printf("Found \"J-Trace ARM Rev.1\" at RVA 0x%08X\n", strpat - (uint8_t*)dllmodule);
            for (uint8_t* lpstrpat = databegin; lpstrpat < dataend - sizeof(lpstrpat) && !found; lpstrpat++) {
                if (*(uint32_t*)lpstrpat == (uint32_t)strpat) {
                    printf("Found g_fwarray at RVA 0x%08X\n", lpstrpat - (uint8_t*)dllmodule);
                    // .text:100B6CD6 BF A8 3A 42 10                       mov     edi, offset g_fwarray
                    // .text:100AEF4B B8 C0 B0 42 10                       mov     eax, offset g_fwarray
                    for (uint8_t* moveedi = codebegin; moveedi < codeend - 0x20 && !found; moveedi++) {
                        if (*moveedi == 0xBF && *(uint32_t*)(moveedi + 1) == (uint32_t)lpstrpat) {
                            printf("Found \"mov edi, offset g_fwarray\" at RVA 0x%08X\n", moveedi - (uint8_t*)dllmodule);
                            //.text:100B6D3B 83 C7 4C                             add     edi, 4Ch
                            //.text:100B6D3E 81 FD 3C 19 00 00                    cmp     ebp, 193Ch
                            //.text:100B6D44 72 9A                                jb      short loc_100B6CE0

                            //.text:100AF60F 83 C7 48                             add     edi, 48h ; 'H'
                            //.text:100AF612 81 FB 60 15 00 00                    cmp     ebx, 1560h
                            //.text:100AF618 72 99                                jb      short loc_100AF5B3
                            // 最好寻找函数结束再往回搜
                            for (uint8_t* cmpebp = moveedi; cmpebp < moveedi + 0x200; cmpebp++) {
                                if ((*(uint16_t*)cmpebp & 0xF0FF) == 0xF081 && *(cmpebp + 6) == 0x72 && (*(cmpebp - 1) == 0x4C || *(cmpebp - 1) == 0x48)) {
                                    uint32_t arraysize = *(uint32_t*)(cmpebp + 2);
                                    itemsize = *(cmpebp - 1);
                                    itemcount = arraysize / itemsize;
                                    g_fwarray = (firmware_rec_s*)lpstrpat;
                                    printf("Found \"cmp exx, %Xh\" at RVA 0x%08X\n", arraysize, cmpebp - (uint8_t*)dllmodule);
                                    found = true;
                                    break;
                                }
                            }
                        }
                        // 7.88f 成了单独函数
                        if (*moveedi == 0xB8 && *(uint32_t*)(moveedi + 1) == (uint32_t)lpstrpat) {
                            printf("Found \"mov eax, offset g_fwarray\" at RVA 0x%08X\n", moveedi - (uint8_t*)dllmodule);
                            //.text:100AEF48 6A 6A                                push    6Ah ; 'j'
                            //.text:100AEF4A 56                                   push    esi
                            for (uint8_t* pushimm = moveedi - 3; pushimm > moveedi - 0x20; pushimm--) {
                                if (*pushimm == 0x6A && pushimm[2] == 0x56) {
                                    //100AEF50 E8 2B FF FF FF                       call    func_outlinefind
                                    if (moveedi[5] == 0xE8) {
                                        // DONE: parse add
                                        itemsize = parseitemsize(moveedi + 10 + *(uint32_t*)(moveedi + 6), 0x100);
                                    } else {
                                        itemsize = 0x58; // fallback
                                    }
                                    itemcount = pushimm[1];
                                    g_fwarray = (firmware_rec_s*)lpstrpat;
                                    printf("Found \"push %d\" at RVA 0x%08X\n", itemcount, pushimm - (uint8_t*)dllmodule);
                                    found = true;
                                    break;
                                }
                            }
                        }
                        // 8.10 是直接push
                        //.text:100AE86C 6A 79                                push    121
                        //.text:100AE86E 68 C0 15 43 10                       push    offset g_fwarray
                        //.text:100AE873 FF 74 24 0C                          push    [esp+8+arg_0]
                        //.text:100AE877 E8 24 FF FF FF                       call    func_outlinefind
                        // 8.12 变成宽push
                        //.text:100C6A8C 68 81 00 00 00                       push    129
                        //.text:100C6A91 68 F0 6F 45 10                       push    offset g_fwarray
                        if (*moveedi == 0x68 && *(uint32_t*)(moveedi + 1) == (uint32_t)lpstrpat) {
                            printf("Found \"push offset g_fwarray\" at RVA 0x%08X\n", moveedi - (uint8_t*)dllmodule);
                            // 寻找下一个call
                            for (uint8_t* call = moveedi; call < moveedi + 0x20; call+=ldisasm(call, false)) {
                                if (*call == 0xE8) {
                                    itemsize = parseitemsize(call + 5 + *(uint32_t*)(call + 1), 0x100);
                                }
                            }
                            if (moveedi[-2] == 0x6A) {
                                itemcount = moveedi[-1];
                                g_fwarray = (firmware_rec_s*)lpstrpat;
                                printf("Found \"push %d\" at RVA 0x%08X\n", itemcount, moveedi - 2 - (uint8_t*)dllmodule);
                                found = true;
                                break;
                            } else if (moveedi[-2] == 0 && moveedi[-5] == 0x68) {
                                itemcount = *(uint32_t*)&moveedi[-4];
                                g_fwarray = (firmware_rec_s*)lpstrpat;
                                printf("Found \"push %d\" at RVA 0x%08X\n", itemcount, moveedi - 5 - (uint8_t*)dllmodule);
                                found = true;
                                break;
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
                        // 本函数是DEFLATE_CopyName, 寻找上一个函数入口 (链接器没有对静态库重排序)
                        //.text:101770E0 8B 44 24 0C                          mov     eax, [esp+wrkmemsize]
                        //.text:101770E4 8B 4C 24 08                          mov     ecx, [esp+wrkmem]
                        //.text:101770E8 83 EC 18                             sub     esp, 18h
                        for (uint8_t* prolog = pushpat; prolog >= pushpat - 0x100; prolog--) {
                            if (*(uint32_t*)prolog == 0x0C24448B && *(uint32_t*)(prolog + 4) == 0x08244C8B) {
                                printfound("DecompressToMem", prolog - (uint8_t*)dllmodule);
                                *(uintptr_t*)&COMPRESS_DecompressToMem = (uintptr_t)prolog;
                                break;
                            }
                        }
                    }
                }
            }
        }
        // 8.10开始COMPRESS_DecompressToMem不再跟DEFLATE_CopyName排在一起, 找Decompressing FW timestamp took %d us (6.14版没有)
        if (!COMPRESS_DecompressToMem) {
            for (uint8_t* strpat = databegin; strpat < dataend - sizeof("Decompressing FW timestamp took %d us") && !COMPRESS_DecompressToMem; strpat++) {
                if (*(uint32_t*)strpat == 'oceD' && memcmp(strpat, "Decompressing FW timestamp took %d us", sizeof("Decompressing FW timestamp took %d us")) == 0) {
                    printf("Found \"Decompressing FW timestamp took %%d us\" at RVA 0x%08X\n", strpat - (uint8_t*)dllmodule);
                    for (uint8_t* pushpat = codebegin; pushpat < codeend - 0x20 && !COMPRESS_DecompressToMem; pushpat++) {
                        //.text:100AE6CB 68 90 61 45 10                       push    offset aDecompressingF ; "Decompressing FW timestamp took %d us"
                        if (*pushpat == 0x68 && *(uint32_t*)(pushpat + 1) == (uint32_t)strpat) {
                            // 往前找push 0
                            //.text:100AE6AE 6A 00                                push    0
                            for (uint8_t* push0 = pushpat; push0 >= pushpat - 0x100 && !COMPRESS_DecompressToMem; push0--) {
                                if (*(uint16_t*)push0 == 0x006A) {
                                    for(uint8_t* call = push0; call != pushpat; call+=ldisasm(call, false)) {
                                        if (*call == 0xE8) {
                                            uint8_t* target = call + 5 + *(uint32_t*)(call + 1);
                                            printfound("DecompressToMem", target - (uint8_t*)dllmodule);
                                            *(uintptr_t*)&COMPRESS_DecompressToMem = (uintptr_t)target;
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if (!COMPRESS_DecompressToMem) {
                errprintf("Missing function DecompressToMem!\n");
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
                            printfound("decodefile", calldest - (uint8_t*)dllmodule);
                            *(uintptr_t*)&func_decodefile = (uintptr_t)calldest;
                            break;
                        }
                    }
                }
            }
        }
        // 8.x, 用 "Error while decompressing RAMCode." 定位
        //.text:100B3B3E E8 7D F6 F5 FF                       call    j__decodefile
        //.text:100B3B43 8B 4C 24 24                          mov     ecx, [esp+104Ch+var_1028]
        //.text:100B3B47 83 C4 14                             add     esp, 14h
        //.text:100B3B4A 3B 41 0C                             cmp     eax, [ecx+0Ch]
        //.text:100B3B4D 74 0A                                jz      short loc_100B3B59
        //.text:100B3B4F 68 94 E6 4C 10                       push    offset aErrorWhileDeco ; "Error while dec
        if (!func_decodefile) {
            for (uint8_t* strpat = databegin; strpat < dataend - sizeof("Error while decompressing RAMCode.") && !func_decodefile; strpat++) {
                if (*(uint32_t*)strpat == 'orrE' && memcmp(strpat, "Error while decompressing RAMCode.", sizeof("Error while decompressing RAMCode.")) == 0) {
                    printf("Found \"Error while decompressing RAMCode.\" at RVA 0x%08X\n", strpat - (uint8_t*)dllmodule);
                    for (uint8_t* pushpat = codebegin; pushpat < codeend - 0x20 && !func_decodefile; pushpat++) {
                        if (*pushpat == 0x68 && *(uint32_t*)(pushpat + 1) == (uint32_t)strpat) {
                            for (uint8_t* call = pushpat - 5; call > pushpat - 0x20; call--) {
                                if (*call == 0xE8) {
                                    uint8_t* calldest = call + *(uint32_t*)(call + 1) + 5;
                                    if (calldest >= codebegin && calldest < codeend) {
                                        printfound("decodefile", calldest - (uint8_t*)dllmodule);
                                        *(uintptr_t*)&func_decodefile = (uintptr_t)calldest;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if (!func_decodefile) {
                colorprintf(FOREGROUND_INTENSITY, "Missing function decodefile, try use local implement\n");
            }
        }
    }
    // 判断是7.22还是v6版长度, 用大小判断不妥, 考虑用版本号
    firmware6_rec_s* fwrec6 = (firmware6_rec_s*)g_fwarray;
    firmware722_rec_s* fwrec7 = g_fwarray;
    firmware_rec_s* fwrec7f = g_fwarray;
    if (found) {
        int localfiles = 0, decodedfiles = 0, saved = 0;
        for (size_t i = 0; i < itemcount; i++, fwrec7f++, fwrec7++, fwrec6++) {
            // 统一为最长的fwrec
            firmware_rec_s via6;
            firmware_rec_s via7;
            firmware_rec_s* fwrec = (itemsize == sizeof(fwrec6))?&via6:(itemsize == sizeof(fwrec7))?&via7:fwrec7f;
            if (itemsize == sizeof(*fwrec6)) {
                via6.displayname = fwrec6->displayname;
                via6.localfile = 0;
                memcpy(&via6.body, &fwrec6->body, sizeof(*fwrec6) - 4);
            }
            if (itemsize == sizeof(*fwrec7)) {
                via7.pub54 = true;
                memcpy(&via7, fwrec7, sizeof(*fwrec7));
            }
            // 历史设计, 数组最后有一个空白记录, 但有itemcount就用不到空白记录
            if (fwrec->displayname == 0) {
                break;
            }
            if (fwrec->decinfo) {
                void(__cdecl*_CopyName)(char*, size_t) = *(void(__cdecl**)(char*, size_t))fwrec->decinfo->functions;
                char algname[16];
                _CopyName(algname, sizeof(algname) - 1);
                printf("%d %s %X->%X", i + 1, algname, fwrec->decinfo->fwlen, fwrec->decinfo->decompresslen);
            } else if (fwrec->localfile) {
                printf("%d file", i + 1);
            } else {
                printf("%d store %X", i + 1, fwrec->len);
            }
            printf(" flash %X ", fwrec->flashspace);
            colorprintf(FOREGROUND_RED|FOREGROUND_GREEN, "%s", fwrec->displayname);
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
                                        decodedfiles++;
                                    }
                                    //fastlz_level1_decompress((uint8_t*)filebuffer + 0x200, st.st_size - 0x200, (uint8_t*)fwbuffer);
                                }
                                if (filetype == 0) {
                                    if (fwrec->usexor) {
                                        xordecode(fwbuffer, filebuffer + 0x200, fwsize);
                                    } else {
                                        memcpy(fwbuffer, filebuffer + 0x200, fwsize);
                                    }
                                    decodedfiles++;
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
        printf("Saved %d of %d firmware.\n", saved, itemcount - 1);
        if (itemsize >= sizeof(firmware722_rec_s) && decodedfiles) {
            printf("There are %d of %d firmware decode from Firmwares folder.\n", decodedfiles, localfiles);
        }
    }

    FreeLibrary(dllmodule);

#ifdef _DEBUG
    _getch();
#endif
	return 0;
}

uint32_t parseitemsize(uint8_t* codeptr, int limit)
{
    while (limit > 0) {
        //text:100AEF0F 83 C7 58                             add     edi, 58h
        if (*codeptr == 0x83 && codeptr[1] == 0xC7u) {
            return codeptr[2];
        }
        size_t oplen = ldisasm(codeptr, false);
        limit -= oplen;
        codeptr += oplen;
    }
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

int colorprintf(WORD color, __in_z __format_string const char * _Format, ...)
{
    HANDLE hCon = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO info;
    GetConsoleScreenBufferInfo(hCon, &info);
    SetConsoleTextAttribute(hCon, color);
    va_list va;
    va_start(va, _Format);
    int len = vfprintf(stderr, _Format, va);
    va_end(va);
    SetConsoleTextAttribute(hCon, info.wAttributes);

    return len;
}

void printfound(const char* name, unsigned int addr)
{
    //printf("Found function decodefile #2 at RVA 0x%08X\n", calldest - (uint8_t*)dllmodule);
    printf("Found function ");
    colorprintf(FOREGROUND_GREEN, "%s", name);
    printf(" at RVA 0x%08X\n", addr);
}

int __cdecl _decodefile(const uint8_t *src, size_t srcLen, uint8_t *dest, size_t destLen)
{
    unsigned int bitBuffer = 0;
    unsigned int extraBits = 0;

    if (srcLen == 0)
        return -101;

    uint8_t header = *src++; // window set 256~16k(wb8~14) encode as 0~6
    srcLen--;

    unsigned int minMatchLength = (header & 7) + 1;
    if (minMatchLength > 7)
        return -104;

    uint32_t bitAccumulator = header >> 3;
    int remainingBitsCount = 5;
    size_t destLeft = destLen;
    int needRefill = 0;
    int offset = 0; // don't place in while

    while (1) {
        int bitsAvailable;
        unsigned int currentBits;
        
        // retrieve bits from bitstream to currentBits
        while (1) {
            bitsAvailable = needRefill + remainingBitsCount;
            currentBits = (bitBuffer << remainingBitsCount) | bitAccumulator;

            // make currentBits is 32bit long
            if (bitsAvailable > 32) {
                bitBuffer >>= 6;
                needRefill = 1;
                bitsAvailable = 32;
            } else if (bitsAvailable == 32) {
                needRefill = bitsAvailable - 32;
                bitBuffer = extraBits >> (40 - bitsAvailable);
            } else {
                while (srcLen--) {
                    extraBits = *src++;
                    currentBits |= extraBits << bitsAvailable;
                    bitsAvailable += 8;

                    if (bitsAvailable >= 32) {
                        break;
                    }
                }

                if (bitsAvailable < 31) {
                    srcLen = 0;
                    bitBuffer = 0;
                    needRefill = 0;
                    if (bitsAvailable < 0)
                        return -101;
                } else {
                    needRefill = bitsAvailable - 32;
                    bitBuffer = extraBits >> (40 - bitsAvailable);
                    bitsAvailable = 32;
                }
            }

            // decide literal or copy
            if ((currentBits & 1) != 0)
                break; // copy

            if (destLeft == 0)
                return -100;

            // literal
            *dest++ = currentBits >> 1;
            destLeft--;
            bitAccumulator = currentBits >> 9; // 1+8
            remainingBitsCount = bitsAvailable - 9;
        }

        // copy match sequence
        unsigned int matchLen;
        unsigned int offsetOrData;
        int offsetBitPosition;
        unsigned int offsetLowBits;

        if ((currentBits & 2) != 0) {
            // longer match length
            int extraLen;
            if ((currentBits & 4) != 0) {
                extraLen = (currentBits >> 3) & 1;
                offsetOrData = currentBits >> 4;
                offsetBitPosition = bitsAvailable - 4;
            } else {
                unsigned int maskBit = 1;
                int masked = 0;

                while (1) {
                    currentBits >>= 2;
                    bitsAvailable -= 2;

                    if ((currentBits & 2) != 0)
                        masked += maskBit;

                    maskBit *= 2;
                    if (maskBit >= 0x80)
                        break;

                    if ((currentBits & 4) != 0) {
                        currentBits >>= 1;
                        bitsAvailable--;
                        break;
                    }
                }

                offsetOrData = currentBits >> 2;
                offsetBitPosition = bitsAvailable - 2;
                extraLen = maskBit + masked;
            }
            matchLen = extraLen + 4;
        } else {
            // shorter match length
            matchLen = ((currentBits >> 2) & 1) + 2;
            offsetOrData = currentBits >> 3;
            offsetBitPosition = bitsAvailable - 3;
        }

        if (matchLen > 0x102)
            return destLen - destLeft; // done, return decoded length

        bitAccumulator = offsetOrData >> 3; // hi 5bit
        remainingBitsCount = offsetBitPosition - 3;
        offsetLowBits = offsetOrData & 7; // lo 3bit

        if (offsetLowBits) {
            int offsetShift;
            int offsetBase;

            if (offsetLowBits < 2) {
                offsetShift = minMatchLength + 1;
                offsetBase = 0;
            } else {
                offsetShift = offsetLowBits + minMatchLength - 1;
                offsetBase = 1 << offsetShift;
            }

            remainingBitsCount -= offsetShift;
            offset = ((bitAccumulator & ((1 << offsetShift) - 1)) | offsetBase) + 1;
            bitAccumulator >>= offsetShift;
        }

        if (matchLen > destLeft)
            return -100; // dest buffer not enough

        destLeft -= matchLen;
        // combine of memcpy(dest, dest - copyPositoin, copyLength), dest += copyLength
        uint8_t* tailSrc = &dest[-offset];
        do {
            *dest++ = *tailSrc++;
        } while (--matchLen);
    }
}