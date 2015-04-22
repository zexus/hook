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

EGLBoolean (*old_eglSwapBuffers)(EGLDisplay dpy, EGLSurface surf) = -1;

EGLBoolean new_eglSwapBuffers(EGLDisplay dpy, EGLSurface surface)
{
    ALOGI("New eglSwapBuffers\n");
    if (old_eglSwapBuffers == -1)
        ALOGE("error\n");
    return old_eglSwapBuffers(dpy, surface);
}

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
    }
    else
    {
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

int MZHOOK_MainEntry(char * pcTargetLib)
{
    int nRet = -1;
    int nFd = -1;

    nFd = open(pcTargetLib, O_RDONLY);
    if (-1 == nFd) {
        ALOGE("[+] Open taget library error\n");
        goto exit;
    }

    void * base_addr = get_module_base(getpid(), pcTargetLib);
    ALOGI("[+] Target Library address = %p\n", base_addr);

    Elf32_Ehdr ehdr;
    read(nFd, &ehdr, sizeof(Elf32_Ehdr));

    unsigned long shdr_addr = ehdr.e_shoff;
    int shnum = ehdr.e_shnum;
    int shent_size = ehdr.e_shentsize;
    unsigned long stridx = ehdr.e_shstrndx;

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
    lseek(nFd, shdr_addr + stridx * shent_size, SEEK_SET);
    read(nFd, &shdr, shent_size);

    char * string_table = (char *)malloc(shdr.sh_size);
    lseek(nFd, shdr.sh_offset, SEEK_SET);
    read(nFd, string_table, shdr.sh_size);
    lseek(nFd, shdr_addr, SEEK_SET);

    int i;
    uint32_t out_addr = 0;
    uint32_t out_size = 0;
    uint32_t got_item = 0;
    int32_t got_found = 0;

    for (i = 0; i < shnum; i++) {
        read(nFd, &shdr, shent_size);
        if (shdr.sh_type == SHT_PROGBITS) {
            int name_idx = shdr.sh_name;
            if (strcmp(&(string_table[name_idx]), ".got.plt") == 0 || strcmp(&(string_table[name_idx]), ".got") == 0) {
                out_addr = base_addr + shdr.sh_addr;
                out_size = shdr.sh_size;
                ALOGI("[+] Got section start_addr = %lx, section_size = %lx\n", out_addr, out_size);

                for (i = 0; i < out_size; i += 4) {
                    got_item = *(uint32_t *)(out_addr + i);
                    if (got_item  == old_eglSwapBuffers) {
                        ALOGI("[+] Found eglSwapBuffers in got section\n");
                        got_found = 1;

                        uint32_t page_size = getpagesize();
                        uint32_t entry_page_start = (out_addr + i) & (~(page_size - 1));
                        mprotect((uint32_t *)entry_page_start, page_size, PROT_READ | PROT_WRITE);
                        *(uint32_t *)(out_addr + i) = new_eglSwapBuffers;

                        break;
                    } else if (got_item == new_eglSwapBuffers) {
                        ALOGI("Already hooked\n");
                        break;
                    }
                }
                if (got_found)
                    break;
            }
        }
    }

    return nRet;

exit:
    if (string_table) {
        free(string_table);
    }

    if (nFd > 0) {
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
        ALOGE("[%s,%d] dlopen pcSrcLib(0x%x) failed\n", \
              __FUNCTION__, __LINE__, pcDstLib);
        goto exit;
    }

    pvLocalAddr = dlsym(pvLocalHandle, pcDstFunc);
    if (NULL == pvLocalAddr)
    {
        ALOGE("[%s,%d] dlsym pcSrcFunc(0x%x) in local_handle(0x%x) failed\n", \
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

    pcSrcLib = "/system/lib/libhook_test.so";
    pcSrcFunc = "new_eglSwapBuffers";

    pvSymbolAddr = MZHOOK_InjectLibToLocal(pcDstLib, pcDstFunc);
    if (NULL == pvSymbolAddr)
    {
        ALOGE("[%s,%d] inject library pcDstLib(%s) to local pcDstFunc(%s) failed\n", \
              __FUNCTION__, __LINE__, pcDstLib, pcDstFunc);
        goto exit;
    }
    old_eglSwapBuffers = pvSymbolAddr;

    //pvSymbolAddr = MZHOOK_InjectLibToLocal(pcSrcLib, pcSrcFunc);
    //if (NULL == pvSymbolAddr)
    //{
    //    ALOGE("[%s,%d] inject library pcSrcLib(%s) to local pcSrcFunc(%s) failed\n", \
    //          __FUNCTION__, __LINE__, pcSrcLib, pcSrcFunc);
    //    goto exit;
    //}
    //new_eglSwapBuffers = pvSymbolAddr;

    nRet = MZHOOK_MainEntry(pcFuncLib);
    if (0 != nRet)
    {
        ALOGE("[%s,%d] inject library pcDstLib(%s) to local pcDstFunc(%s) failed\n", \
              __FUNCTION__, __LINE__, pcDstLib, pcDstFunc);
        goto exit;
    }

exit:
    return nRet;
}
