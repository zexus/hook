#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <android/log.h>
#include <EGL/egl.h>
#include <GLES/gl.h>
#include <elf.h>
#include <fcntl.h>
#include <sys/mman.h>

#define ENABLE_DEBUG 1

#if ENABLE_DEBUG
    #define TAG "INJECT"
    #define ALOGV(...) __android_log_print(ANDROID_LOG_VERBOSE, TAG, __VA_ARGS__)
    #define ALOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
    #define ALOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
    #define ALOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__)
    #define ALOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)
    #define ALOGF(...) __android_log_print(ANDROID_LOG_FATAL, TAG, __VA_ARGS__)
    #define ASTDERR(...)
#else
    #define ALOGV(...)
    #define ALOGD(...)
    #define ALOGI(...)
    #define ALOGW(...)
    #define ALOGE(...)
    #define ALOGF(...)
    #define ASTDERR(...)
#endif

void * MZHOOK_GetModuleBase(pid_t nTargetPid, const char * pcModuleName)
{
    long lModuleAddr = 0;
    char szFileName[32];
    char szLine[1024];
    FILE * pcFileDes;
    char * pcString;

    if (nTargetPid < 0)
    {
        snprintf(szFileName, sizeof(szFileName), "/proc/self/maps");
    }
    else
    {
        snprintf(szFileName, sizeof(szFileName), "/proc/%d/maps", nTargetPid);
    }

    pcFileDes = fopen(szFileName, "r");
    if (NULL != pcFileDes)
    {
        while (fgets(szLine, sizeof(szLine), pcFileDes))
        {
            if (strstr(szLine, pcModuleName))
            {
                pcString = strtok(szLine, "-");
                lModuleAddr = strtoul(pcString, NULL, 16);
                if (lModuleAddr == 0x8000)
                {
                    lModuleAddr = 0;
                }

                break;
            }
        }
        fclose(pcFileDes) ;
    }

    return (void *)lModuleAddr;
}

int MZHOOK_MainEntry(char * pcTargetLib, char * s_fnOnEldFunctionAddress, char * s_fnOnNewFunctionAddress)
{
    int nRet = -1;
    int nFd = -1;
    int nShnum = -1;
    int nShentSize = -1;
    unsigned long ulShdrAddr;
    unsigned long ulStrIdx;

    nFd = open(pcTargetLib, O_RDONLY);
    if (-1 == nFd)
    {
        ALOGE("[%s,%d] open pcTargetLib(0x%lx) failed\n", \
              __FUNCTION__, __LINE__, pcTargetLib);
        goto exit;
    }

    void * pvBaseAddr = MZHOOK_GetModuleBase(getpid(), pcTargetLib);
    if (NULL == pvBaseAddr)
    {
        ALOGE("[%s,%d] get module base pcTargetLib(0x%lx) addr failed\n", \
              __FUNCTION__, __LINE__, pcTargetLib);
        goto exit;
    }

    Elf32_Ehdr sEhdr;

    nRet = read(nFd, &sEhdr, sizeof(Elf32_Ehdr));
    if (-1 == nRet)
    {
        ALOGE("[%s,%d] read section head sEhdr(0x%lx) data failed\n", \
              __FUNCTION__, __LINE__, sEhdr);
        goto exit;
    }

    ulShdrAddr = sEhdr.e_shoff;
    nShnum = sEhdr.e_shnum;
    nShentSize = sEhdr.e_shentsize;
    ulStrIdx = sEhdr.e_shstrndx;

    /*
     *节区头部数据结构描述
     *
     *typedef struct {
     *   Elf32_Word sh_name;                // 节区名称
     *   Elf32_Word sh_type;                // 节区类型
     *   Elf32_Word sh_flags;               // 标志描述属性
     *   Elf32_Word sh_addr;                // 节区出现在内存映像中时给出节区第一个字节应处的位置
     *   Elf32_Word sh_offset;              // 节区第一字节与文件头之间的偏移
     *   Elf32_Word sh_size;                // 节区的长度
     *   Elf32_Word sh_link;                // 节区头部索引链接
     *   Elf32_Word sh_info;                // 附加信息
     *   Elf32_Word sh_addralign;           // 某些节区带有地址对齐约束
     *   Elf32_Word sh_entsize;             // 某些节区中包含固定大小的项目，如符号表
     *}Elf32_Shdr
    */
    Elf32_Shdr shdr;
    lseek(nFd, ulShdrAddr + ulStrIdx * nShentSize, SEEK_SET);
    read(nFd, &shdr, nShentSize);

    char * string_table = (char *)malloc(shdr.sh_size);
    lseek(nFd, shdr.sh_offset, SEEK_SET);
    read(nFd, string_table, shdr.sh_size);
    lseek(nFd, ulShdrAddr, SEEK_SET);

    int i;
    uint32_t nOutAddr = 0;
    uint32_t nOutSize = 0;
    uint32_t nGotItem = 0;
    int32_t nGotFound = 0;

    for (i = 0; i < nShnum; i++)
    {
        read(nFd, &shdr, nShentSize);
        if (shdr.sh_type == SHT_PROGBITS)
        {
            int name_idx = shdr.sh_name;
            if (strcmp(&(string_table[name_idx]), ".got.plt") == 0 || strcmp(&(string_table[name_idx]), ".got") == 0)
            {
                nOutAddr = pvBaseAddr + shdr.sh_addr;
                nOutSize = shdr.sh_size;

                for (i = 0; i < nOutSize; i += 4)
                {
                    nGotItem = *(uint32_t *)(nOutAddr + i);
                    if (nGotItem  == s_fnOnEldFunctionAddress)
                    {
                        ALOGI("[%s,%d] found 0x%lx int got section\n", __FUNCTION__, __LINE__, s_fnOnEldFunctionAddress);
                        nGotFound = 1;
                        uint32_t page_size = getpagesize();
                        uint32_t entry_page_start = (nOutAddr + i) & (~(page_size - 1));
                        mprotect((uint32_t *)entry_page_start, page_size, PROT_READ | PROT_WRITE);
                        *(uint32_t *)(nOutAddr + i) = s_fnOnNewFunctionAddress;
                        break;
                    }
                    else if (nGotItem == s_fnOnNewFunctionAddress)
                    {
                        ALOGI("Already hooked\n");
                        break;
                    }
                }
                if (nGotFound)
                    break;
            }
        }
    }

    nRet = 0;

exit:
    if (string_table)
    {
        free(string_table);
    }

    if (nFd > 0)
    {
        close(nFd);
    }

    return nRet;
}

void * MZHOOK_InjectLibToLocal(char * pcDstLib, char * pcDstFunc)
{
    int nRet = -1;
    void * pvLocalHandle = NULL;
    void * pvLocalAddr = NULL;

    pvLocalHandle = dlopen(pcDstLib, RTLD_NOW | RTLD_GLOBAL);
    if (NULL == pvLocalHandle)
    {
        ALOGE("[%s,%d] dlopen pcSrcLib(%s) failed\n", \
              __FUNCTION__, __LINE__, pcDstLib);
        goto exit;
    }

    pvLocalAddr = dlsym(pvLocalHandle, pcDstFunc);
    if (NULL == pvLocalAddr)
    {
        ALOGE("[%s,%d] dlsym pcDstFunc(%s) in pvLocalHandle(0x%lx) failed\n", \
              __FUNCTION__, __LINE__, pcDstFunc, pvLocalHandle);
        goto exit;
    }

exit:
    return pvLocalAddr;
}

int hook_entry(char * pcFuncLib, char * pcSrcLib, char * pcDstLib, char * pcSrcFunc, char * pcDstFunc)
{
    int nRet = -1;
    void * pvSymbolAddr = NULL;
    void * s_fnOnEldFunctionAddress = NULL;
    void * s_fnOnNewFunctionAddress = NULL;

    pvSymbolAddr = MZHOOK_InjectLibToLocal(pcFuncLib, pcDstFunc);
    if (NULL == pvSymbolAddr)
    {
        ALOGE("[%s,%d] inject library pcFuncLib(%s) to local pcDstFunc(%s) failed\n", \
              __FUNCTION__, __LINE__, pcFuncLib, pcDstFunc);
        goto exit;
    }
    s_fnOnEldFunctionAddress = pvSymbolAddr;

    pvSymbolAddr = MZHOOK_InjectLibToLocal(pcSrcLib, pcSrcFunc);
    if (NULL == pvSymbolAddr)
    {
        ALOGE("[%s,%d] inject library pcSrcLib(%s) to local pcSrcFunc(%s) failed\n", \
              __FUNCTION__, __LINE__, pcSrcLib, pcSrcFunc);
        goto exit;
    }
    s_fnOnNewFunctionAddress = pvSymbolAddr;

    nRet = MZHOOK_MainEntry(pcDstLib, s_fnOnEldFunctionAddress, s_fnOnNewFunctionAddress);
    if (0 != nRet)
    {
        ALOGE("[%s,%d] inject library pcDstLib(%s) to local pcDstFunc(%s) failed\n", \
              __FUNCTION__, __LINE__, pcDstLib, pcDstFunc);
        goto exit;
    }

exit:
    return nRet;
}
