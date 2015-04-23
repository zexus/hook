#include <stdio.h>
#include <stdlib.h>
#include <sys/user.h>
#include <asm/ptrace.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <dirent.h>
#include <unistd.h>
#include <string.h>
#include <elf.h>
#include <android/log.h>

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

#define CPSR_T_MASK     ( 1u << 5 )

const char * pcLibcPath = "/system/lib/libc.so";
const char * pcLinkerPath = "/system/bin/linker";

extern int hook_entry(char *pcTargetLib);

static void * MZHOOK_GetModuleBase(pid_t nTargetPid, const char * pcModuleName)
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
    if (NULL == pcFileDes)
    {
        ALOGE("[%s,%d] open szFileName(%s) failed\n", \
              __FUNCTION__, __LINE__, szFileName);
        return NULL;
    }

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

static void * MZHOOK_GetRemoteAddr(pid_t nTargetPid, const char * pcModuleName, void * pcLocalAddr)
{
    void * pvLocalHandle = NULL;
    void * pvRemoteHandle = NULL;

    pvLocalHandle = MZHOOK_GetModuleBase(-1, pcModuleName);
    if (NULL == pvLocalHandle)
    {
        ALOGE("[%s,%d] get self process module base address pcModuleName(0x%lx) failed\n", \
              __FUNCTION__, __LINE__, pcModuleName);
        return NULL;
    }

    pvRemoteHandle = MZHOOK_GetModuleBase(nTargetPid, pcModuleName);
    if (NULL == pvRemoteHandle)
    {
        ALOGE("[%s,%d] get nTargetPid(%d) process module base pcModuleName address(0x%lx) failed\n", \
              __FUNCTION__, __LINE__, nTargetPid, pcModuleName);
        return NULL;
    }

    void * pvTargetAddr = (void *)((uint32_t)pcLocalAddr + (uint32_t)pvRemoteHandle - (uint32_t)pvLocalHandle);
    if (NULL == pvTargetAddr)
    {
        ALOGE("[%s,%d] process module base remote address failed pcLocalAddr(0x%lx) pvRemoteHandle(0x%lx) pvLocalHandle(0x%lx)\n", \
              __FUNCTION__, __LINE__, pcLocalAddr, pvRemoteHandle, pvLocalHandle);
        return NULL;
    }

    return pvTargetAddr;
}

int MZHOOK_FindPidOfProcess(const char * pcProcessName)
{
    int nId;
    pid_t nTargetPid = -1;
    DIR * pcDirectory = NULL;
    FILE * pcFileDes = NULL;
    char szFileName[32];
    char szCmdLine[256];
    struct dirent * sDirectoryEntry;

    if (NULL == pcProcessName)
    {
        ALOGE("[%s,%d] invalid parameters pcProcessName(%s)\n", \
              __FUNCTION__, __LINE__, pcProcessName);
        return -1;
    }

    pcDirectory = opendir("/proc");
    if (NULL == pcDirectory)
    {
        ALOGE("[%s,%d] open proc dir(0x%lx) failed\n", \
              __FUNCTION__, __LINE__, pcDirectory);
        return -1;
    }

    while(NULL != (sDirectoryEntry = readdir(pcDirectory)))
    {
        nId = atoi(sDirectoryEntry->d_name);
        if (0 != nId)
        {
            sprintf(szFileName, "/proc/%d/cmdline", nId);
            pcFileDes = fopen(szFileName, "r");
            if (pcFileDes)
            {
                fgets(szCmdLine, sizeof(szCmdLine), pcFileDes);
                fclose(pcFileDes);

                if (strcmp(pcProcessName, szCmdLine) == 0)
                {
                    nTargetPid = nId;
                    break;
                }
            }
        }
    }

    closedir(pcDirectory);
    return nTargetPid;
}

static int MZHOOK_PtrCallWrapper(pid_t nTargetPid, const char * pcFuncName, void * pvFuncAddr, long * plParams, int nParamNum, struct pt_regs * sTempRegs)
{
    int nRet = -1;

    if (nTargetPid < 0 || NULL == pvFuncAddr || NULL == plParams
        || 0 > nParamNum || NULL == sTempRegs)
    {
        ALOGE("[%s,%d] invalid parameters: nTargetPid(%d) pvFuncAddr(0x%lx) plParams(0x%lx) \
              nParaNum(%d) sTempRegs(0x%lx)\n", \
              __FUNCTION__, __LINE__, nTargetPid, pvFuncAddr, plParams, nParamNum, sTempRegs);
        return -1;
    }

    nRet = ptrace_call(nTargetPid, (uint32_t)pvFuncAddr, plParams, nParamNum, sTempRegs);
    if (-1 == nRet)
    {
        ALOGE("[%s,%d] ptrace call: nTargetPid(%d) pvFuncAddr(0x%lx) plParams(0x%lx) \
              nParaNum(%d) sTempRegs(0x%lx) failed\n", \
              __FUNCTION__, __LINE__, nTargetPid, pvFuncAddr, plParams, nParamNum, sTempRegs);
        return -1;
    }

    nRet = ptrace_getregs(nTargetPid, sTempRegs);
    if (-1 == nRet)
    {
        ALOGE("[%s,%d] get register from nTargetPid(%d) failed sTempRegs(0x%lx)\n", \
              __FUNCTION__, __LINE__, nTargetPid, sTempRegs);
        return -1;
    }

    return 0;
}

static int MZHOOK_InjectProToRemote(pid_t nTargetPid, const char * pcFuncLib, const char * pcSrcLib, const char * pcDstLib, const char * pcSrcFunc, const char * pcDstFunc)
{
    int nRet = -1;
    long alParams[10];
    void * pvMmapAddr = NULL;
    void * pvDlopenAddr = NULL;
    void * pvDlsymAddr = NULL;
    void * pvDlcloseAddr = NULL;
    void * pvDlerrorAddr = NULL;
    uint8_t * pnMapBase = NULL;
    struct pt_regs sTempRegs, sOrinRegs;

    if (0 > nTargetPid || NULL == pcFuncLib || NULL == pcSrcLib
        || NULL == pcDstLib || NULL == pcSrcFunc || NULL == pcDstFunc)
    {
        ALOGE("[%s,%d] invalid parameters: nTargetPid(%d) pcFuncLib(%s) pcSrcLib(%s) \
              pcDstLib(%s) pcSrcFunc(%s) pcDstFunc(%s)\n", \
              __FUNCTION__, __LINE__, nTargetPid, pcFuncLib, pcSrcLib, pcDstLib, pcSrcFunc, pcDstFunc);
        goto exit;
    }

    ALOGI("[%s,%d] injecting process: nTargetPid(%d)\n", \
          __FUNCTION__, __LINE__, nTargetPid);

    nRet = ptrace_attach(nTargetPid);
    if (-1 == nRet)
    {
        ALOGE("[%s,%d] attach nTargetPid(%d) failed\n", \
              __FUNCTION__, __LINE__, nTargetPid);
        goto exit;
    }

    nRet = ptrace_getregs(nTargetPid, &sTempRegs);
    if (-1 == nRet)
    {
        ALOGE("[%s,%d] get registers from nTargetPid(%d) failed\n", \
              __FUNCTION__, __LINE__, nTargetPid);
        goto exit;
    }
    memcpy(&sOrinRegs, &sTempRegs, sizeof(sTempRegs));

    alParams[0] = 0;
    alParams[1] = 0x4000;
    alParams[2] = PROT_READ | PROT_WRITE | PROT_EXEC;
    alParams[3] =  MAP_ANONYMOUS | MAP_PRIVATE;
    alParams[4] = 0;
    alParams[5] = 0;
    pvMmapAddr = MZHOOK_GetRemoteAddr(nTargetPid, pcLibcPath, (void *)mmap);

    if (MZHOOK_PtrCallWrapper(nTargetPid, "mmap", pvMmapAddr, alParams, 6, &sTempRegs) == -1)
        goto exit;

    pnMapBase = ptrace_retval(&sTempRegs);

    pvDlopenAddr = MZHOOK_GetRemoteAddr(nTargetPid, pcLinkerPath, (void *)dlopen);
    pvDlsymAddr = MZHOOK_GetRemoteAddr(nTargetPid, pcLinkerPath, (void *)dlsym);
    pvDlcloseAddr = MZHOOK_GetRemoteAddr(nTargetPid, pcLinkerPath, (void *)dlclose);
    pvDlerrorAddr = MZHOOK_GetRemoteAddr(nTargetPid, pcLinkerPath, (void *)dlerror);

    ptrace_writedata(nTargetPid, pnMapBase, "/system/lib/libhook.so", strlen("/system/lib/libhook.so") + 1);

    alParams[0] = pnMapBase;
    alParams[1] = RTLD_NOW | RTLD_GLOBAL;

    nRet = MZHOOK_PtrCallWrapper(nTargetPid, "dlopen", pvDlopenAddr, alParams, 2, &sTempRegs);
    if (-1 == nRet)
    {
        ALOGE("[%s,%d] ptrace call wrapper nTargetPid(%d) pvDlopenAddr(0x%lx) alParams(0x%lx) failed\n", \
              __FUNCTION__, __LINE__, nTargetPid, pvDlopenAddr, alParams);
        goto exit;
    }

    void * pvLibHandle = ptrace_retval(&sTempRegs);

#define FUNCTION_NAME_ADDR_OFFSET       (0x100)
    ptrace_writedata(nTargetPid, pnMapBase + FUNCTION_NAME_ADDR_OFFSET, "hook_entry", strlen("hook_entry") + 1);
    alParams[0] = pvLibHandle;
    alParams[1] = pnMapBase + FUNCTION_NAME_ADDR_OFFSET;

    nRet = MZHOOK_PtrCallWrapper(nTargetPid, "dlsym", pvDlsymAddr, alParams, 2, &sTempRegs);
    if (-1 == nRet)
    {
        ALOGE("[%s,%d] ptrace call wrapper nTargetPid(%d) pvDlsymAddr(0x%lx) alParams(0x%lx) failed\n", \
              __FUNCTION__, __LINE__, nTargetPid, pvDlsymAddr, alParams);
        goto exit;
    }

    void * pvHookEntryAddr = ptrace_retval(&sTempRegs);
    if (NULL ==  pvHookEntryAddr)
    {
        ALOGE("[%s,%d] find entry addr(0x%lx) failed\n", \
          __FUNCTION__, __LINE__, pvHookEntryAddr);
        goto exit;
    }

    ALOGI("[%s,%d] enter to entry addr(0x%lx)\n", \
          __FUNCTION__, __LINE__, pvHookEntryAddr);

#define FUNCTION_FUNC_LIB_OFFSET      (0x200)
    ptrace_writedata(nTargetPid, pnMapBase + FUNCTION_FUNC_LIB_OFFSET, pcFuncLib, strlen(pcFuncLib) + 1);
    alParams[0] = pnMapBase + FUNCTION_FUNC_LIB_OFFSET;

#define FUNCTION_SRC_LIB_OFFSET      (0x300)
    ptrace_writedata(nTargetPid, pnMapBase + FUNCTION_SRC_LIB_OFFSET, pcSrcLib, strlen(pcSrcLib) + 1);
    alParams[1] = pnMapBase + FUNCTION_SRC_LIB_OFFSET;

#define FUNCTION_DST_LIB_OFFSET      (0x400)
    ptrace_writedata(nTargetPid, pnMapBase + FUNCTION_DST_LIB_OFFSET, pcDstLib, strlen(pcDstLib) + 1);
    alParams[2] = pnMapBase + FUNCTION_DST_LIB_OFFSET;

#define FUNCTION_SRC_FUNC_OFFSET      (0x500)
    ptrace_writedata(nTargetPid, pnMapBase + FUNCTION_SRC_FUNC_OFFSET, pcSrcFunc, strlen(pcSrcFunc) + 1);
    alParams[3] = pnMapBase + FUNCTION_SRC_FUNC_OFFSET;

#define FUNCTION_DST_FUNC_OFFSET      (0x600)
    ptrace_writedata(nTargetPid, pnMapBase + FUNCTION_DST_FUNC_OFFSET, pcDstFunc, strlen(pcDstFunc) + 1);
    alParams[4] = pnMapBase + FUNCTION_DST_FUNC_OFFSET;

    nRet = MZHOOK_PtrCallWrapper(nTargetPid, "hook_entry", pvHookEntryAddr, alParams, 5, &sTempRegs);
    if (-1 == nRet)
    {
        ALOGE("[%s,%d] ptrace call wrapper nTargetPid(%d) pvHookEntryAddr(0x%lx) alParams(0x%lx) failed\n", \
              __FUNCTION__, __LINE__, nTargetPid, pvHookEntryAddr, alParams);
        goto exit;
    }

    alParams[0] = pvLibHandle;

    nRet = MZHOOK_PtrCallWrapper(nTargetPid, "dlclose", dlclose, alParams, 1, &sTempRegs);
    if (-1 == nRet)
    {
        ALOGE("[%s,%d] ptrace call wrapper nTargetPid(%d) dlclose(0x%lx) alParams(0x%lx) failed\n", \
              __FUNCTION__, __LINE__, nTargetPid, dlclose, alParams);
        goto exit;
    }

    ptrace_setregs(nTargetPid, &sOrinRegs);
    ptrace_detach(nTargetPid);
    nRet = 0;

exit:
    return nRet;
}

static int MZHOOK_InjectLibToLocal(pid_t nTargetPid, const char * pcSrcLib, const char * pcSrcFunc, const char * pcDstFunc)
{
    int nRet = -1;
    unsigned char acBuf[4];
    void * pvLocalHandle, * pvLocalAddr;
    unsigned long ulDstAddr, ulDstEntry;
    unsigned long ulRemoteAddr;

    if (ptrace_attach(nTargetPid) == -1)
        goto exit;

    nRet = find_func_by_got(nTargetPid, pcDstFunc, &ulDstAddr, &ulDstEntry);
    if (0 != nRet || NULL == ulDstAddr || NULL == ulDstEntry)
    {
        ALOGE("[%s,%d] failed nTargetPid(%d) pcDstFunc(0x%x)\n", \
              __FUNCTION__, __LINE__, nTargetPid, pcDstFunc);
        goto exit;
    }

    ALOGI("[%s,%d] pcDstFunc(%s) found by got addr(0x%lx) entry(0x%lx) \n", \
      __FUNCTION__, __LINE__, pcDstFunc, ulDstEntry, ulDstAddr);

    pvLocalHandle = dlopen(pcSrcLib, RTLD_NOW | RTLD_GLOBAL);
    if (NULL == pvLocalHandle)
    {
        ALOGE("[%s,%d] dlopen pcSrcLib(0x%x) failed\n", \
              __FUNCTION__, __LINE__, pcSrcLib);
        goto exit;
    }

    pvLocalAddr = dlsym(pvLocalHandle, pcSrcFunc);
    if (NULL == pvLocalAddr)
    {
        ALOGE("[%s,%d] dlsym pcSrcFunc(0x%x) in local_handle(0x%x) failed\n", \
              __FUNCTION__, __LINE__, pcSrcFunc, pvLocalHandle);
        goto exit;
    }

    ulRemoteAddr = MZHOOK_GetRemoteAddr(nTargetPid, pcSrcLib, pvLocalAddr);
    acBuf[0] = (ulRemoteAddr&0xFF);
    acBuf[1] = (ulRemoteAddr&0xFF00) >> 8;
    acBuf[2] = (ulRemoteAddr&0xFF0000) >> 16;
    acBuf[3] = (ulRemoteAddr&0xFF000000) >> 24;

    ptrace_writedata(nTargetPid, ulDstAddr, acBuf, 4);

    nRet = 0;

exit:
    ptrace_detach(nTargetPid);
    return nRet;
}

static int MZHOOK_InjectLibToRemote(pid_t nTargetPid, const char * pcSrcLib)
{
    int nRet = -1;
    long alParams[6];
    void * pvMmapAddr = NULL;
    void * pvDlopenAddr = NULL;
    uint8_t * pnMapBase = NULL;
    struct pt_regs sTempRegs, sOrinRegs;

    if (0 > nTargetPid || NULL == pcSrcLib)
    {
        ALOGE("[%s,%d] invalid parameters: nTargetPid(%d) or pcSrcLib(0x%x)\n", \
              __FUNCTION__, __LINE__, nTargetPid, pcSrcLib);
        return -1;
    }

    nRet = ptrace_attach(nTargetPid);
    if (-1 == nRet)
    {
        ALOGE("[%s,%d] attach nTargetPid(%d) failed\n", \
              __FUNCTION__, __LINE__, nTargetPid);
        goto exit;
    }

    nRet = ptrace_getregs(nTargetPid, &sTempRegs);
    if (-1 == nRet)
    {
        ALOGE("[%s,%d] get registers from nTargetPid(%d) failed\n", \
              __FUNCTION__, __LINE__, nTargetPid);
        goto exit;
    }
    memcpy(&sOrinRegs, &sTempRegs, sizeof(sTempRegs));

    pvMmapAddr = MZHOOK_GetRemoteAddr(nTargetPid, pcLibcPath, (void *)mmap);

    alParams[0] = 0;
    alParams[1] = 0x4000;
    alParams[2] = PROT_READ | PROT_WRITE | PROT_EXEC;
    alParams[3] =  MAP_ANONYMOUS | MAP_PRIVATE;
    alParams[4] = 0;
    alParams[5] = 0;

    if (MZHOOK_PtrCallWrapper(nTargetPid, "mmap", pvMmapAddr, alParams, 6, &sTempRegs) == -1)
        goto exit;

    pnMapBase = ptrace_retval(&sTempRegs);

    pvDlopenAddr = MZHOOK_GetRemoteAddr(nTargetPid, pcLinkerPath, (void *)dlopen );

    ptrace_writedata(nTargetPid, pnMapBase, pcSrcLib, strlen(pcSrcLib) + 1);

    alParams[0] = pnMapBase;
    alParams[1] = RTLD_NOW | RTLD_GLOBAL;

    nRet = MZHOOK_PtrCallWrapper(nTargetPid, "dlopen", pvDlopenAddr, alParams, 2, &sTempRegs);
    if (-1 == nRet)
    {
        ALOGE("[%s,%d] ptrace call wrapper nTargetPid(%d) pvDlopenAddr(0x%lx) alParams(0x%lx) failed\n", \
              __FUNCTION__, __LINE__, nTargetPid, pvDlopenAddr, alParams);
        goto exit;
    }

    void * pvLibHandle = ptrace_retval(&sTempRegs);
    if (NULL == pvLibHandle)
    {
        ALOGE("[+] Call dlopen in remote process error\n");
        goto exit;
    }

exit:
    ptrace_setregs(nTargetPid, &sOrinRegs);
    ptrace_detach(nTargetPid);
    return nRet;
}

int main(int argc, char** argv)
{
    int nRet = -1;
    pid_t nTargetPid;

    char * pcSrcLib = "/system/lib/libhook_test.so";
    char * pcDstLib = "/system/lib/libEGL.so";
    char * pcFuncLib = "/system/lib/libsurfaceflinger.so";
    char * pcSrcFunc = "new_eglSwapBuffers";
    char * pcDstFunc = "eglSwapBuffers";

    if (NULL == pcDstLib)
    {
        char* end = NULL;
        if (argv[1][0] == '-' && argv[1][1] == 'n')
        {
            nTargetPid = strtol(argv[2], &end, 10);
        }
        else
        {
            ALOGE("[%s,%d] invalid parameters\n", \
                  __FUNCTION__, __LINE__);
            return -1;
        }

        nRet = MZHOOK_InjectLibToRemote(nTargetPid, pcSrcLib);
        if (0 != nRet)
        {
            ALOGE("[%s,%d] inject source library(%s) to  remote pid(%d) failed\n", \
                  __FUNCTION__, __LINE__, pcSrcLib, nTargetPid);
            return -1;
        }

        nRet = MZHOOK_InjectLibToLocal(nTargetPid, pcSrcLib, pcSrcFunc, pcDstFunc);
        if (0 != nRet)
        {
            ALOGE("[%s,%d] inject source library(%s) to  local pid(%d) failed\n", \
                  __FUNCTION__, __LINE__, pcSrcLib, getpid());
            return -1;
        }
    }
    else
    {
        nTargetPid = MZHOOK_FindPidOfProcess("/system/bin/surfaceflinger");
        nRet = MZHOOK_InjectProToRemote(nTargetPid, pcFuncLib, pcSrcLib, pcDstLib, pcSrcFunc, pcDstFunc);
        if (0 != nRet)
        {
            ALOGE("[%s,%d] inject source library(%s) to  local pid(%d) failed\n", \
                  __FUNCTION__, __LINE__, pcSrcLib, getpid());
            return -1;
        }
    }

    return 0;
}
