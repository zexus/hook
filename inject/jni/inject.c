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

const char *libc_path = "/system/lib/libc.so";
const char *linker_path = "/system/bin/linker";

extern int hook_entry(char *pcTargetLib);

void* get_module_base(pid_t pid, const char* module_name)
{
    FILE *fp;
    long addr = 0;
    char *pch;
    char filename[32];
    char line[1024];

    if (pid < 0)
    {
        snprintf(filename, sizeof(filename), "/proc/self/maps");
    } else {
        snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
    }

    fp = fopen(filename, "r");

    if (fp != NULL) {
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, module_name)) {
                pch = strtok( line, "-" );
                addr = strtoul( pch, NULL, 16 );

                if (addr == 0x8000)
                    addr = 0;

                break;
            }
        }

        fclose(fp) ;
    }

    return (void *)addr;
}

void* get_remote_addr(pid_t target_pid, const char* module_name, void* local_addr)
{
    void* local_handle, *remote_handle;

    local_handle = get_module_base(-1, module_name);
    remote_handle = get_module_base(target_pid, module_name);

    void * ret_addr = (void *)((uint32_t)local_addr + (uint32_t)remote_handle - (uint32_t)local_handle);

    return ret_addr;
}

int find_pid_of(const char *process_name)
{
    int id;
    pid_t pid = -1;
    DIR* dir;
    FILE *fp;
    char filename[32];
    char cmdline[256];

    struct dirent * entry;

    if (process_name == NULL)
        return -1;

    dir = opendir("/proc");
    if (dir == NULL)
        return -1;

    while((entry = readdir(dir)) != NULL)
    {
        id = atoi(entry->d_name);
        if (id != 0) {
            sprintf(filename, "/proc/%d/cmdline", id);
            fp = fopen(filename, "r");
            if (fp) {
                fgets(cmdline, sizeof(cmdline), fp);
                fclose(fp);

                if (strcmp(process_name, cmdline) == 0)
                {
                    pid = id;
                    break;
                }
            }
        }
    }

    closedir(dir);
    return pid;
}

int ptrace_call_wrapper(pid_t target_pid, const char * func_name, void * func_addr, long * parameters, int param_num, struct pt_regs * regs)
{
    if (ptrace_call(target_pid, (uint32_t)func_addr, parameters, param_num, regs) == -1)
        return -1;

    if (ptrace_getregs(target_pid, regs) == -1)
        return -1;

    return 0;
}

int MZHOOK_InjectProToRemote(pid_t nTargetPid, const char * pcFuncLib, const char * pcSrcLib, const char * pcDstLib, const char * pcSrcFunc, const char * pcDstFunc)
{
    int nRet = -1;
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
        ALOGE("[%s,%d] Invalid Parameters: nTargetPid(%d) pcFuncLib(%s) pcSrcLib(%s) \
              pcDstLib(%s) pcSrcFunc(%s) pcDstFunc(%s)\n", \
              __FUNCTION__, __LINE__, nTargetPid, pcFuncLib, pcSrcLib, pcDstLib, pcSrcFunc, pcDstFunc);
        goto exit;
    }

    long alParams[10];

    ALOGI("[%s,%d] Injecting process: nTargetPid(%d)\n", \
          __FUNCTION__, __LINE__, nTargetPid);

    if (ptrace_attach(nTargetPid) == -1)
        goto exit;

    if (ptrace_getregs(nTargetPid, &sTempRegs) == -1)
        goto exit;

    memcpy(&sOrinRegs, &sTempRegs, sizeof(sTempRegs));

    pvMmapAddr = get_remote_addr(nTargetPid, libc_path, (void *)mmap);

    alParams[0] = 0;
    alParams[1] = 0x4000;
    alParams[2] = PROT_READ | PROT_WRITE | PROT_EXEC;
    alParams[3] =  MAP_ANONYMOUS | MAP_PRIVATE;
    alParams[4] = 0;
    alParams[5] = 0;

    if (ptrace_call_wrapper(nTargetPid, "mmap", pvMmapAddr, alParams, 6, &sTempRegs) == -1)
        goto exit;

    pnMapBase = ptrace_retval(&sTempRegs);

    pvDlopenAddr = get_remote_addr(nTargetPid, linker_path, (void *)dlopen);
    pvDlsymAddr = get_remote_addr(nTargetPid, linker_path, (void *)dlsym);
    pvDlcloseAddr = get_remote_addr(nTargetPid, linker_path, (void *)dlclose);
    pvDlerrorAddr = get_remote_addr(nTargetPid, linker_path, (void *)dlerror);

    ptrace_writedata(nTargetPid, pnMapBase, "/system/lib/libhook.so", strlen("/system/lib/libhook.so") + 1);

    alParams[0] = pnMapBase;
    alParams[1] = RTLD_NOW | RTLD_GLOBAL;

    if (ptrace_call_wrapper(nTargetPid, "dlopen", pvDlopenAddr, alParams, 2, &sTempRegs) == -1)
        goto exit;

    void * sohandle = ptrace_retval(&sTempRegs);

#define FUNCTION_NAME_ADDR_OFFSET       0x100
    ptrace_writedata(nTargetPid, pnMapBase + FUNCTION_NAME_ADDR_OFFSET, "hook_entry", strlen("hook_entry") + 1);
    alParams[0] = sohandle;
    alParams[1] = pnMapBase + FUNCTION_NAME_ADDR_OFFSET;

    if (ptrace_call_wrapper(nTargetPid, "dlsym", pvDlsymAddr, alParams, 2, &sTempRegs) == -1)
        goto exit;

    void * hook_entry_addr = ptrace_retval(&sTempRegs);
    ALOGI("[+] hook_entry_addr = %p\n", hook_entry_addr);

#define FUNCTION_PARAM_ADDR_OFFSET      0x200
    ptrace_writedata(nTargetPid, pnMapBase + FUNCTION_PARAM_ADDR_OFFSET, pcFuncLib, strlen(pcFuncLib) + 1);
    alParams[0] = pnMapBase + FUNCTION_PARAM_ADDR_OFFSET;

#define FUNCTION_PARAM_ADDR_OFFSET      0x300
    ptrace_writedata(nTargetPid, pnMapBase + FUNCTION_PARAM_ADDR_OFFSET, pcSrcLib, strlen(pcSrcLib) + 1);
    alParams[1] = pnMapBase + FUNCTION_PARAM_ADDR_OFFSET;

#define FUNCTION_PARAM_ADDR_OFFSET      0x400
    ptrace_writedata(nTargetPid, pnMapBase + FUNCTION_PARAM_ADDR_OFFSET, pcDstLib, strlen(pcDstLib) + 1);
    alParams[2] = pnMapBase + FUNCTION_PARAM_ADDR_OFFSET;

#define FUNCTION_PARAM_ADDR_OFFSET      0x500
    ptrace_writedata(nTargetPid, pnMapBase + FUNCTION_PARAM_ADDR_OFFSET, pcSrcFunc, strlen(pcSrcFunc) + 1);
    alParams[3] = pnMapBase + FUNCTION_PARAM_ADDR_OFFSET;

#define FUNCTION_PARAM_ADDR_OFFSET      0x600
    ptrace_writedata(nTargetPid, pnMapBase + FUNCTION_PARAM_ADDR_OFFSET, pcDstFunc, strlen(pcDstFunc) + 1);
    alParams[4] = pnMapBase + FUNCTION_PARAM_ADDR_OFFSET;

    if (ptrace_call_wrapper(nTargetPid, "hook_entry", hook_entry_addr, alParams, 5, &sTempRegs) == -1)
        goto exit;

    alParams[0] = sohandle;

    if (ptrace_call_wrapper(nTargetPid, "dlclose", dlclose, alParams, 1, &sTempRegs) == -1)
        goto exit;

    ptrace_setregs(nTargetPid, &sOrinRegs);
    ptrace_detach(nTargetPid);
    nRet = 0;

exit:
    return nRet;
}

int MZHOOK_InjectLibToLocal(pid_t nTargetPid, const char * pcSrcLib, const char * pcSrcFunc, const char * pcDstFunc)
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

    ALOGI("[+] %s found by got addr: 0x%lx entry: 0x%lx\n", pcDstFunc, ulDstEntry, ulDstAddr);

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

    ulRemoteAddr = get_remote_addr(nTargetPid, pcSrcLib, pvLocalAddr);

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

int MZHOOK_InjectLibToRemote(pid_t nTargetPid, const char * pcSrcLib)
{
    int nRet = -1;
    void *pvMmapAddr, *pvDlopenAddr;
    uint8_t * pnMapBase = NULL;

    struct pt_regs regs, original_regs;

    long alParams[6];

    if (0 > nTargetPid || NULL == pcSrcLib)
    {
        ALOGE("[%s,%d] invalid parameters: nTargetPid(%d) or pcSrcLib(0x%x)\n", \
              __FUNCTION__, __LINE__, nTargetPid, pcSrcLib);
        return -1;
    }

    if (ptrace_attach(nTargetPid) == -1)
        goto exit;

    if (ptrace_getregs(nTargetPid, &regs) == -1)
        goto exit;

    memcpy(&original_regs, &regs, sizeof(regs));

    pvMmapAddr = get_remote_addr(nTargetPid, libc_path, (void *)mmap);
    ALOGI("[+] Remote mmap address: %x\n", pvMmapAddr);

    alParams[0] = 0;
    alParams[1] = 0x4000;
    alParams[2] = PROT_READ | PROT_WRITE | PROT_EXEC;
    alParams[3] =  MAP_ANONYMOUS | MAP_PRIVATE;
    alParams[4] = 0;
    alParams[5] = 0;

    if (ptrace_call_wrapper(nTargetPid, "mmap", pvMmapAddr, alParams, 6, &regs) == -1)
        goto exit;

    pnMapBase = ptrace_retval(&regs);

    pvDlopenAddr = get_remote_addr(nTargetPid, linker_path, (void *)dlopen );

    ALOGI("[+] Get imports: dlopen: %x\n", pvDlopenAddr);

    ptrace_writedata(nTargetPid, pnMapBase, pcSrcLib, strlen(pcSrcLib) + 1);

    alParams[0] = pnMapBase;
    alParams[1] = RTLD_NOW | RTLD_GLOBAL;

    if (ptrace_call_wrapper(nTargetPid, "dlopen", pvDlopenAddr, alParams, 2, &regs) == -1)
        goto exit;

    void * sohandle = ptrace_retval(&regs);
    if (NULL == sohandle)
    {
        ALOGE("[+] Call dlopen in remote process error\n");
        goto exit;
    }

    nRet = 0;

exit:
    ptrace_setregs(nTargetPid, &original_regs);
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
        nTargetPid = find_pid_of("/system/bin/surfaceflinger");
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
