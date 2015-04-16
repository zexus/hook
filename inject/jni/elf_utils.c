#include <stdio.h>
#include <errno.h>
#include <elf.h>
#include <sys/ptrace.h>
#include <android/log.h>

#define ENABLE_DEBUG 1

#if ENABLE_DEBUG
#define  LOG_TAG "INJECT"
#define  LOGD(fmt, args...)  __android_log_print(ANDROID_LOG_DEBUG,LOG_TAG, fmt, ##args)
#define DEBUG_PRINT(format,args...) LOGD(format, ##args)
#else
#define DEBUG_PRINT(format,args...)
#endif

typedef union
{
	long value;
	char chars[sizeof(long)];
}WORDUN;

int ptrace_read_bytes(pid_t pid, const unsigned long *src, void *buf, size_t size)
{
	int wordCount, byteRemain;
	const unsigned long *srcAddr;
	long *dstAddr;
	WORDUN un;
	int i;

	if (pid < 0 || src == NULL || buf == NULL || size < 0)
    {
		return EINVAL;
	}

	wordCount = size / sizeof(long);
	byteRemain = size % sizeof(long);
	srcAddr = src;
	dstAddr = buf;

	for (i = 0; i < wordCount; i++, srcAddr++, dstAddr++)
    {
		errno = 0;

		// *(dstAddr) = ptrace(PTRACE_POKETEXT, pid, srcAddr, NULL);
		*(dstAddr) = ptrace(PTRACE_PEEKDATA, pid, srcAddr, NULL);
		if (errno != 0)
        {
			DEBUG_PRINT("PEEKDATA from addr 0x%lx failed %d %s\n", srcAddr, errno, strerror(errno));
			return errno;
		}
	}


	if (byteRemain > 0)
    {
		errno = 0;

		// un.value = ptrace(PTRACE_POKETEXT, pid, dest, d.val);  // write
		un.value = ptrace(PTRACE_PEEKDATA, pid, srcAddr, NULL);
		if (errno != 0)
        {
			DEBUG_PRINT("PEEKDATA from addr 0x%lx failed %d %s\n", srcAddr, errno, strerror(errno));
			return errno;
		}

		for (i = 0; i < byteRemain; i++)
			((char*)dstAddr)[i] = un.chars[i];
	}

	return 0;
}

int ptrace_write_bytes(pid_t pid, unsigned long *dst, const void *buf, size_t size)
{
	int wordCount, byteRemain;
	unsigned long *dstAddr;
	const long *dataAddr;
	WORDUN un;
	int i;

	if (dst == NULL || buf == NULL || size < 0)
	{
		DEBUG_PRINT("[+] ptrace_write_bytes invalid params\n");
		return EINVAL;
	}

	wordCount = size / sizeof(long);
	byteRemain = size % sizeof(long);
	dstAddr = dst;
	dataAddr = buf;

	for (i = 0; i < wordCount; i++, dstAddr++, dataAddr++)
	{
		if (ptrace(PTRACE_POKEDATA, pid, dstAddr, (void*) (*dataAddr)) != 0)
		{
			DEBUG_PRINT("POKEDATA to 0x%lx failed %d\n", dstAddr, errno);
			return errno;
		}
	}

	if (byteRemain > 0)
	{
		un.value = ptrace(PTRACE_PEEKDATA, pid, dstAddr, NULL);
		if (errno != 0)
		{
			DEBUG_PRINT("PEEKDATA in write bytes failed %d\n", errno);
			return errno;
		}

		for (i = 0; i < byteRemain; i++)
		{
			un.chars[i] = ((char*) dataAddr)[i];
		}

		if (ptrace(PTRACE_POKEDATA, pid, dstAddr, (void*) (un.value)) != 0)
		{
			DEBUG_PRINT("POKEDATA 0x%lx failed %d\n", dstAddr, errno);
			return errno;
		}
	}

	return 0;
}

int ptrace_strlen(pid_t pid, const unsigned long *addr)
{
	int len = 0;
	int i;
	WORDUN un;

	if (pid > 0)
    {
		while (1)
        {
			un.value = ptrace(PTRACE_PEEKDATA, pid, addr, 0);
			for (i = 0; i < sizeof(long); i++)
            {
				if (un.chars[i] != '\0')
					len++;
				else
					return len;
			}
			addr++;
		}
	}
    else
    {
		len = strlen((const char*) addr);
	}

	return len;
}

char* ptrace_get_str(pid_t pid, const unsigned long *addr)
{
	char* result = NULL;
	int strLen = 0;
	// int ret = 0;

	if (addr == NULL)
		return NULL;

	strLen = ptrace_strlen(pid, addr);

	if (strLen > 0)
    {
		result = malloc(strLen + 1);
		ptrace_read_bytes(pid, addr, result, strLen);
		result[strLen] = '\0';
	}

	return result;
}

static int read_data(pid_t pid, void* src, void* buf, size_t size)
{
	int nRet = 0;

	if (pid == 0)
    {
		memcpy(buf, src, size);
	}
    else
    {
		nRet = ptrace_read_bytes(pid, src, buf, size);
	}

	return nRet;
}

int find_name_by_pid(pid_t pid, char* buf, size_t size)
{
	char path[64] = { 0 };

    if (buf == NULL || size <= 0)
        return -EINVAL;

	if (pid <= 0)
		snprintf(path, sizeof(path), "/proc/self/exe", pid);
	else
		snprintf(path, sizeof(path), "/proc/%d/exe", pid);

    if (readlink(path, buf, size) < 0)
        return errno;

    // buf[size - 1] = '\0';

    return 0;
}

void * get_module_base_internal(pid_t pid, const char* module_name)
{
	FILE* fin = NULL;
	char path[256] = { 0 }, line[1024] = { 0 }, selfname[1024] = {0};
	long addr = 0;
	char* pch;

	if (module_name == NULL)
    {
		if (find_name_by_pid(pid, selfname, 1024) != 0)
        {
			DEBUG_PRINT("find name by pid %d failed %d\n", pid, errno);
			return errno;
		}
	}

	// ALOGI("find %s by pid %d\n", selfname, pid);

	if (pid <= 0)
    {
		snprintf(path, sizeof(path), "/proc/self/maps");
	}
    else
    {
		snprintf(path, sizeof(path), "/proc/%d/maps", pid);
	}

	if ((fin = fopen(path, "r")) == NULL)
		return errno;

	while (fgets(line, sizeof(line), fin) != NULL)
    {
		if (strstr(line, module_name == NULL ? selfname : module_name) != NULL)
        {
			pch = strtok(line, "-");
			addr = strtoul(pch, NULL, 16);
			if (0x8000 == addr)
            {
				addr = 0;
			}

			break;
		}
		memset(line, 0, sizeof(line));
	}

	fclose(fin);

	return (void *)addr;
}

unsigned long * image_start_addr(pid_t pid)
{
	unsigned long * value;
	value = get_module_base_internal(pid, NULL);
	return value;
}

int find_func_by_got(pid_t pid, const char* name, unsigned long* entry_addr, unsigned long* entry_value)
{
	volatile int ret = -1;
	volatile Elf32_Ehdr *pEhdr = NULL, ehdr;
	volatile Elf32_Phdr *pPhdr = NULL, phdr;
	volatile Elf32_Dyn  *pDyn = NULL, dyn;
	volatile Elf32_Sym *pSym = NULL, sym;
    volatile Elf32_Rel *pRel = NULL, rel;

    char* image_base = NULL;
	char* pStrTable;
    char* pBuf;

	long totalRelaSize, relEnt = sizeof(rel);
	int i;

	if (entry_addr == NULL && entry_value == NULL)
    {
		return -EINVAL;
    }

	// ehdr->phdr->dynamic->rela->sym: name@symbol and vaddr@offset
	// rela has the name index in sym and the vaddr of the .got.plt entry
	image_base = (char*)image_start_addr(pid);
	pEhdr = (Elf32_Ehdr*)image_base;

	/**
	-------------------------------------------------------------------------
	Program Header				Section Header
	typedef struct {			typedef struct {
		Elf32_Word p_type;			Elf32_Word sh_name;
		Elf32_Off  p_offset;		Elf32_Word sh_type;
		Elf32_Addr p_vaddr;			Elf32_Word sh_flags;
		Elf32_Addr p_paddr;			Elf32_Addr sh_addr;
		Elf32_Word p_filesz;		Elf32_Off  sh_offset;
		Elf32_Word p_memsz;			Elf32_Word sh_size;
		Elf32_Word p_flags;			Elf32_Word sh_link;
		Elf32_Word p_align;			Elf32_Word sh_info;
	} Elf32_phdr;					Elf32_Word sh_addralign;
                                    Elf32_Word sh_entsize;
                                }Elf32_Shdr;
	-------------------------------------------------------------------------
	**/

	if ((ret = read_data(pid, pEhdr, &ehdr, sizeof(ehdr))) != 0)
    {
		DEBUG_PRINT("%s: read ehdr failed\n", __FUNCTION__);
		return ret;
	}

	pDyn = NULL;

	for (i = 0, pPhdr = (Elf32_Phdr*) ((char*) pEhdr + ehdr.e_phoff); i < ehdr.e_phnum; i++, pPhdr++)
    {

		if ((ret = read_data(pid, pPhdr, &phdr, sizeof(phdr))) != 0)
        {
			DEBUG_PRINT("%s: read phdr failed\n", __FUNCTION__);
			return ret;
		}

		if (phdr.p_type == PT_DYNAMIC)
        {
			pDyn = (Elf32_Dyn*) (image_base + phdr.p_vaddr);
			break;
		}
	}

	if (pDyn == NULL)
    {
		return -1;
	}

	if ((ret = read_data(pid, pDyn, &dyn, sizeof(dyn))) != 0)
    {
		return ret;
	}

	while (dyn.d_tag != DT_NULL)
    {
		switch (dyn.d_tag)
        {
			case DT_JMPREL:
				pRel = (Elf32_Rel*)(image_base + dyn.d_un.d_ptr);
				break;
			case DT_PLTRELSZ:
				totalRelaSize = dyn.d_un.d_val;
				break;
			case DT_SYMTAB:
				pSym = (Elf32_Sym*)(image_base + dyn.d_un.d_ptr);
				break;
			case DT_STRTAB:
				pStrTable = (char*)(image_base + dyn.d_un.d_ptr);
				break;
			default:
				break;
		}

		pDyn++;
		if ((ret = read_data(pid, pDyn, &dyn, sizeof(dyn))) != 0)
        {
			return ret;
		}
	}

	if (pRel == NULL || pSym == NULL || pStrTable == NULL)
    {
		DEBUG_PRINT("%s: cannot find dynamic sections\n", __FUNCTION__);
		return -1;
	}

	if (totalRelaSize == 0)
    {
		DEBUG_PRINT("%s: total rela size is 0\n", __FUNCTION__);
		return -1;
	}

	if (relEnt == 0)
    {
		DEBUG_PRINT("%s: cannot find rela entry size, set to %d\n", __FUNCTION__, sizeof(rel));
		relEnt = sizeof(rel);
	}

	for (i = 0; i < totalRelaSize / relEnt; i++, pRel++)
    {
		// read a rela entry
		if ((ret = read_data(pid, pRel, &rel, sizeof(rel))) != 0)
        {
			return ret;
		}

		// read a symbol in sym table
		ret = read_data(pid, pSym + ELF32_R_SYM(rel.r_info),&sym, sizeof(sym));

		if (ret != 0)
        {
			DEBUG_PRINT("%s read rel entry %d failed\n", __FUNCTION__, i);
			return ret;
		}

		if (pid == 0)
        {
			if (strcmp(name, pStrTable + sym.st_name) == 0)
            {
				if (entry_addr != NULL)
					*entry_addr = rel.r_offset;
				if (entry_value != NULL)
					*entry_value = *((long*)rel.r_offset);
			}
		}
        else
        {
			pBuf = ptrace_get_str(pid, (const long*)(pStrTable + sym.st_name));
			if (pBuf != NULL) {
				if (pBuf[0] != '\0' && strcmp(name, pBuf) == 0) {
					free(pBuf);
					ret = 0;
					if (entry_addr != NULL)
						*entry_addr = image_base + rel.r_offset;
					if (entry_value != NULL)
						ret = read_data(pid, (void*)(*entry_addr), entry_value, sizeof(long));
					return ret;
				}
				free(pBuf);
			}
		}

	}

	return ret;
}
