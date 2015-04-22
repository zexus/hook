#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <android/log.h>
#include <EGL/egl.h>
#include <GLES/gl.h>
#include <elf.h>
#include <fcntl.h>
#include <sys/mman.h>

#define ENABLE_DEBUG 1

#if ENABLE_DEBUG
#define LOG_TAG "HOOK"
#define LOGD(fmt, args...)  __android_log_print(ANDROID_LOG_DEBUG,LOG_TAG, fmt, ##args)
#define DEBUG_PRINT(format,args...) LOGD(format, ##args)
#else
#define DEBUG_PRINT(format,args...)
#endif

EGLBoolean (*old_eglSwapBuffers)(EGLDisplay dpy, EGLSurface surf) = -1;

EGLBoolean new_eglSwapBuffers(EGLDisplay dpy, EGLSurface surface)
{
    DEBUG_PRINT("New eglSwapBuffers\n");
    if (old_eglSwapBuffers == -1)
        DEBUG_PRINT("error\n");
    return old_eglSwapBuffers(dpy, surface);
}

void* get_module_base(pid_t pid, const char* module_name)
{
    FILE *fp;
    long addr = 0;
    char *pch;
    char filename[32];
    char line[1024];

    if (pid < 0) {
        /* self process */
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

int MZHOOK_MainEntry(char * pcTargetLib)
{
    int nRet = -1;
    int nFd = -1;

    nFd = open(pcTargetLib, O_RDONLY);
    if (-1 == nFd) {
        DEBUG_PRINT("[+] Open taget library error\n");
        goto exit;
    }

    void * base_addr = get_module_base(getpid(), pcTargetLib);
    DEBUG_PRINT("[+] Target Library address = %p\n", base_addr);

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
                DEBUG_PRINT("[+] Got section start_addr = %lx, section_size = %lx\n", out_addr, out_size);

                for (i = 0; i < out_size; i += 4) {
                    got_item = *(uint32_t *)(out_addr + i);
                    if (got_item  == old_eglSwapBuffers) {
                        DEBUG_PRINT("[+] Found eglSwapBuffers in got section\n");
                        got_found = 1;

                        uint32_t page_size = getpagesize();
                        uint32_t entry_page_start = (out_addr + i) & (~(page_size - 1));
                        mprotect((uint32_t *)entry_page_start, page_size, PROT_READ | PROT_WRITE);
                        *(uint32_t *)(out_addr + i) = new_eglSwapBuffers;

                        break;
                    } else if (got_item == new_eglSwapBuffers) {
                        DEBUG_PRINT("Already hooked\n");
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

int hook_entry(char * pcFuncLib, char * pcDstLib, char * pcSrcFunc, char * pcDstFunc)
{
    //D/HOOK    (12636): [+] Start hooking /system/lib/libEGL.so
    //D/HOOK    (12636): [+] Start hooking /system/lib/libsurfaceflinger.so
    //D/HOOK    (12636): [+] Start hooking new_eglSwapBuffers
    //D/HOOK    (12636): [+] Start hooking eglSwapBuffers
    old_eglSwapBuffers = eglSwapBuffers;
    MZHOOK_MainEntry(pcFuncLib);
    return 0;
}
