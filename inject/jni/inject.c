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
#define  LOG_TAG "INJECT"
#define  LOGD(fmt, args...)  __android_log_print(ANDROID_LOG_DEBUG,LOG_TAG, fmt, ##args)
#define DEBUG_PRINT(format,args...) LOGD(format, ##args)
#else
#define DEBUG_PRINT(format,args...)
#endif

#define CPSR_T_MASK     ( 1u << 5 )

const char *libc_path = "/system/lib/libc.so";
const char *linker_path = "/system/bin/linker";
const char *libhook_path = "/system/lib/libhook.so";

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

    DEBUG_PRINT("[+] get_remote_addr: local[%x], remote[%x]\n", local_handle, remote_handle);

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

    while((entry = readdir(dir)) != NULL) {
        id = atoi(entry->d_name);
        if (id != 0) {
            sprintf(filename, "/proc/%d/cmdline", id);
            fp = fopen(filename, "r");
            if (fp) {
                fgets(cmdline, sizeof(cmdline), fp);
                fclose(fp);

                if (strcmp(process_name, cmdline) == 0) {
                    /* process found */
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
    DEBUG_PRINT("[+] Calling %s in target process.\n", func_name);
    if (ptrace_call(target_pid, (uint32_t)func_addr, parameters, param_num, regs) == -1)
        return -1;

    if (ptrace_getregs(target_pid, regs) == -1)
        return -1;

    DEBUG_PRINT("[+] Target process returned from %s, return value=%x, pc=%x \n", func_name, ptrace_retval(regs), ptrace_ip(regs));

    return 0;
}

int inject_remote_process(pid_t target_pid, const char *library_path, const char *function_name, const char *param, size_t param_size)
{
    int ret = -1;
    void *mmap_addr, *dlopen_addr, *dlsym_addr, *dlclose_addr, *dlerror_addr;
    uint8_t *map_base = 0;

    struct pt_regs regs, original_regs;

    long parameters[10];

    DEBUG_PRINT("[+] Injecting process: %d\n", target_pid);

    if (ptrace_attach(target_pid) == -1)
        goto exit;

    if (ptrace_getregs(target_pid, &regs) == -1)
        goto exit;

    memcpy(&original_regs, &regs, sizeof(regs));

    mmap_addr = get_remote_addr(target_pid, libc_path, (void *)mmap);
    DEBUG_PRINT("[+] Remote mmap address: %x\n", mmap_addr);

    parameters[0] = 0;
    parameters[1] = 0x4000;
    parameters[2] = PROT_READ | PROT_WRITE | PROT_EXEC;
    parameters[3] =  MAP_ANONYMOUS | MAP_PRIVATE;
    parameters[4] = 0;
    parameters[5] = 0;

    if (ptrace_call_wrapper(target_pid, "mmap", mmap_addr, parameters, 6, &regs) == -1)
        goto exit;

    map_base = ptrace_retval(&regs);

    dlopen_addr = get_remote_addr( target_pid, linker_path, (void *)dlopen );
    dlsym_addr = get_remote_addr( target_pid, linker_path, (void *)dlsym );
    dlclose_addr = get_remote_addr( target_pid, linker_path, (void *)dlclose );
    dlerror_addr = get_remote_addr( target_pid, linker_path, (void *)dlerror );

    DEBUG_PRINT("[+] Get imports: dlopen: %x, dlsym: %x, dlclose: %x, dlerror: %x\n",
            dlopen_addr, dlsym_addr, dlclose_addr, dlerror_addr);

    ptrace_writedata(target_pid, map_base, library_path, strlen(library_path) + 1);

    parameters[0] = map_base;
    parameters[1] = RTLD_NOW | RTLD_GLOBAL;

    if (ptrace_call_wrapper(target_pid, "dlopen", dlopen_addr, parameters, 2, &regs) == -1)
        goto exit;

    void * sohandle = ptrace_retval(&regs);

#define FUNCTION_NAME_ADDR_OFFSET       0x100
    ptrace_writedata(target_pid, map_base + FUNCTION_NAME_ADDR_OFFSET, function_name, strlen(function_name) + 1);
    parameters[0] = sohandle;
    parameters[1] = map_base + FUNCTION_NAME_ADDR_OFFSET;

    if (ptrace_call_wrapper(target_pid, "dlsym", dlsym_addr, parameters, 2, &regs) == -1)
        goto exit;

    void * hook_entry_addr = ptrace_retval(&regs);
    DEBUG_PRINT("[+] hook_entry_addr = %p\n", hook_entry_addr);

#define FUNCTION_PARAM_ADDR_OFFSET      0x200
    ptrace_writedata(target_pid, map_base + FUNCTION_PARAM_ADDR_OFFSET, param, strlen(param) + 1);
    parameters[0] = map_base + FUNCTION_PARAM_ADDR_OFFSET;

    if (ptrace_call_wrapper(target_pid, "hook_entry", hook_entry_addr, parameters, 1, &regs) == -1)
        goto exit;

    //printf("Press enter to dlclose and detach\n");
    //getchar();
    parameters[0] = sohandle;

    if (ptrace_call_wrapper(target_pid, "dlclose", dlclose, parameters, 1, &regs) == -1)
        goto exit;

    ptrace_setregs(target_pid, &original_regs);
    ptrace_detach(target_pid);
    ret = 0;

exit:
    return ret;
}

int inject_local_library(pid_t target_pid, const char *library_path, const char *function_name)
{
    int ret = -1;
    void *local_handle, *entry_addr;
    unsigned long value1;

    if (ptrace_attach(target_pid) == -1)
        goto exit;

    unsigned long addr, value;
    const char* tofind = "Hook_Entry_Test";
    ret = find_func_by_got(target_pid, tofind, &addr, &value);
    DEBUG_PRINT("%s found by got addr: 0x%lx entry: 0x%lx\n", tofind, value, addr);

    local_handle = dlopen(library_path, RTLD_NOW | RTLD_GLOBAL);
    if (NULL == local_handle)
    {
        DEBUG_PRINT("dlopen error, %s", dlerror());
        return -1;
    }

    entry_addr = dlsym(local_handle, function_name);
    if (NULL == entry_addr)
    {
        DEBUG_PRINT("dlsym error, %s", dlerror());
        return -1;
    }

    value1 = get_remote_addr(target_pid, "/system/lib/libhook_test.so", entry_addr);

    unsigned char buf[4];
    buf[0] = value1&0xFF;
    buf[1] = (value1&0xFF00) >> 8;
    buf[2] = (value1&0xFF0000) >> 16;
    buf[3] = (value1&0xFF000000) >> 24;
    ptrace_writedata(target_pid, addr, buf, 4);

    ptrace_detach(target_pid);
    ret = 0;

exit:
    return ret;
}

int inject_remote_library(pid_t target_pid, const char * library_path)
{
    int ret = -1;
    void *mmap_addr, *dlopen_addr;
    uint8_t *map_base = 0;

    struct pt_regs regs, original_regs;

    long parameters[6];

    DEBUG_PRINT("[+] Injecting process: %d\n", target_pid);

    if (ptrace_attach(target_pid) == -1)
        goto exit;

    if (ptrace_getregs(target_pid, &regs) == -1)
        goto exit;

    memcpy(&original_regs, &regs, sizeof(regs));

    mmap_addr = get_remote_addr(target_pid, libc_path, (void *)mmap);
    DEBUG_PRINT("[+] Remote mmap address: %x\n", mmap_addr);

    parameters[0] = 0;
    parameters[1] = 0x4000;
    parameters[2] = PROT_READ | PROT_WRITE | PROT_EXEC;
    parameters[3] =  MAP_ANONYMOUS | MAP_PRIVATE;
    parameters[4] = 0;
    parameters[5] = 0;

    if (ptrace_call_wrapper(target_pid, "mmap", mmap_addr, parameters, 6, &regs) == -1)
        goto exit;

    map_base = ptrace_retval(&regs);

    dlopen_addr = get_remote_addr( target_pid, linker_path, (void *)dlopen );

    DEBUG_PRINT("[+] Get imports: dlopen: %x\n", dlopen_addr);

    ptrace_writedata(target_pid, map_base, library_path, strlen(library_path) + 1);

    parameters[0] = map_base;
    parameters[1] = RTLD_NOW | RTLD_GLOBAL;

    if (ptrace_call_wrapper(target_pid, "dlopen", dlopen_addr, parameters, 2, &regs) == -1)
        goto exit;

    void * sohandle = ptrace_retval(&regs);
    if (NULL == sohandle)
    {
        DEBUG_PRINT("[+] Call dlopen in remote process error\n");
        goto exit;
    }

    ret = 0;

exit:
    ptrace_setregs(target_pid, &original_regs);
    ptrace_detach(target_pid);
    return ret;
}

int main(int argc, char** argv)
{
    pid_t target_pid;
    int nRet = -1;

    char* end = NULL;
    if (argv[1][0] == '-' && argv[1][1] == 'n')
    {
        target_pid = strtol(argv[2], &end, 10);
    }

    nRet = inject_remote_library(target_pid, "/system/lib/libhook_test.so");
    nRet = inject_local_library(target_pid, "/system/lib/libhook_test.so", "New_Hook_Entry_Test");
    if (0 != nRet)
    {
        DEBUG_PRINT("Inject local process %d error\n", target_pid);
        return -1;
    }

    target_pid = find_pid_of("/system/bin/surfaceflinger");
    if (-1 == target_pid)
    {
        DEBUG_PRINT("Can't find the process\n");
        return -1;
    }

    nRet = inject_remote_process(target_pid, libhook_path, "hook_entry",  "/system/lib/libsurfaceflinger.so", strlen("/system/lib/libsurfaceflinger.so"));
    if (0 != nRet)
    {
        DEBUG_PRINT("Inject remote process %d error\n", target_pid);
        return -1;
    }

    return 0;
}
