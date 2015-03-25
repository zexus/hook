/************************************************************************
xxx
All rights reserved.

File Name:
Summary:
Current Version:
Author:

History:
Ver 1.0.0, Zexus, 2015.03.24
Add “switch windows” function for recording

Ver 0.0.0, xx, 2015.03.24
Original version

**************************************************************************/

#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <errno.h>
#include <dlfcn.h>
#include "log.h"

#include "elf_util.h"
#include "ptrace_util.h"
// Attention: Do not dereference any remote pointer, use read functions


#if defined(ANDROID)
const char *LIBC_PATH = "/system/lib/libc.so";
const char *LINKER_PATH = "/system/bin/linker";

#elif defined(LINUX)
#if __WORDSIZE == 64
const char *LIBC_PATH = "/lib/x86_64-linux-gnu/libc-2.15.so";
const char *LINKER_PATH = "/lib/x86_64-linux-gnu/libdl-2.15.so";
#else
const char *LIBC_PATH = "/lib/libc.so.6";
const char *LINKER_PATH = "/lib/libdl.so.2";
#endif
#endif


static int find_name_by_pid(pid_t pid, char* buf, size_t size);

// read local or remote data
static int read_data(pid_t pid, void* src, void* buf, size_t size) {
	int ret = 0;
	if (pid == 0)
		memcpy(buf, src, size);
	else
		ret = ptrace_read_bytes(pid, src, buf, size);

	return ret;
}

// free carefully for embedded pointer
typedef struct {
    const char      *pdynstr;      /* Dynamic string table */
    ElfW(Sym)       *pdynsym;      /* Dynamic symbol table */
    int            nbuckets;     /* # hash buckets */
    int            symndx;       /* Index of 1st dynsym in hash */
    unsigned int   maskwords_bm; /* # Bloom filter words, minus 1 */
    unsigned int   shift2;       /* Bloom filter hash shift */
    const unsigned long     *pbloom;       /* Bloom filter words */
    const unsigned int      *pbuckets;     /* Hash buckets */
    const unsigned int      *phashval;     /* Hash value array. this is just a remote pointer */
    unsigned long			base;
} hash_state_t;

static void free_hash_state(hash_state_t* p) {
	if (p != NULL) {

		if (p->pbloom != NULL)
			free((void*) p->pbloom);
		if (p->pbuckets != NULL)
			free((void*) p->pbuckets);

		free(p);
	}
}

// not tested, not used. just for reference
static unsigned int dl_elf_hash(const char* str) {
	if (str == NULL)
		return 0;

	unsigned int h = 0, g;

	while (*str != '\n') {
		h = (h << 4) + *str++;
		if ((g = h & 0xf0000000) != 0)
			h ^= g >> 24;
		h &= ~g;
	}

	return h;
}

static unsigned int dl_gnu_hash(const char* str) {
	if (str == NULL)
		return 0;
    unsigned char c;
	unsigned int h = 5381;
	for (c = *str; c != '\0'; c=*++str)
		h = (h << 5) + h + c;

	// some algorithm may use this, but gnu not
	//return h & 0x7fffffff;
	return h;
}

static int find_sym_by_hash(pid_t pid, const hash_state_t* pstat, const char* symname, unsigned long *value) {

	int ret = -1;
	if (pstat == NULL || value == NULL)
		return -EINVAL;

	unsigned int c;
	unsigned int h1, h2;
	unsigned int n;
	unsigned long bitmask = -1;
	const ElfW(Sym) *psym, sym;
	unsigned int *phashval;
	void *pBuf = NULL;

	/*
	 * Hash the name, generate the "second" hash
	 * from it for the Bloom filter.
	 */
	h1 = dl_gnu_hash(symname);
	h2 = h1 >> pstat->shift2;

	/* Test against the Bloom filter */
	c = sizeof(long) * 8;
	// maskwords is one-bit-set number to present the number of bloom
	// the max index used to access it has to minus 1
	n = (h1 / c) & (pstat->maskwords_bm - 1);
	bitmask = ((long)1 << (h1 % c)) | ((long)1 << (h2 % c));

	if ((pstat->pbloom[n] & bitmask) != bitmask)
		return -1;

	/* Locate the hash chain, and corresponding hash value element */
	n = pstat->pbuckets[h1 % pstat->nbuckets];
	if (n == 0) /* Empty hash chain, symbol not present */
		return -1;

	psym = pstat->pdynsym + n;
	phashval = pstat->phashval + (n - pstat->symndx);

	/*
	 * Walk the chain until the symbol is found or
	 * the chain is exhausted.
	 */
	for (h1 &= ~1; 1; psym++, phashval++) {

		if ((ret = read_data(pid, phashval, &h2, sizeof(h2))) != 0)
			return ret;

		if ((ret = read_data(pid, psym, &sym, sizeof(sym))) != 0)
			return ret;

		/*
		 * Compare the strings to verify match. Note that
		 * a given hash chain can contain different hash
		 * values. We'd get the right result by comparing every
		 * string, but comparing the hash values first lets us
		 * screen obvious mismatches at very low cost and avoid
		 * the relatively expensive string compare.
		 *
		 * We are intentionally glossing over some things here:
		 *
		 *    -  We could test sym->st_name for 0, which indicates
		 *   a NULL string, and avoid a strcmp() in that case.
		 *
		 *    - The real runtime linker must also take symbol
		 *  versioning into account. This is an orthogonal
		 *  issue to hashing, and is left out of this
		 *  example for simplicity.
		 *
		 * A real implementation might test (h1 == (h2 & ~1), and then
		 * call a (possibly inline) function to validate the rest.
		 */
		pBuf = ptrace_get_str(pid, (const long*) (pstat->pdynstr + sym.st_name));
		if (pBuf != NULL) {
			if ((h1 == (h2 & ~1)) && strcmp(symname, pBuf) == 0) {
				*value = pstat->base + sym.st_value;
				free(pBuf);
				return 0;
			}
			free(pBuf);
			pBuf = NULL;
		}

		/* Done if at end of chain */
		if (h2 & 1)
			break;
	}

	/* This object does not have the desired symbol */

	return -1;
}


// TODO I found that the section table is NOT mapped into the process space at runtime
// how to get the dyn sym count without reading the module file?

/*
static int getDynsymCount(pid_t pid, const struct link_map *plm) {
	if (plm == NULL)
		return 0;

	struct link_map lm;
	ElfW(Ehdr) *pEhdr, ehdr;
	ElfW(Shdr) *pShdr, shdr;
	int ret = -1;
	int i;

	if (pid == 0)
		pEhdr = (ElfW(Ehdr)*)plm->l_addr;
	else {
		if ((ret = read_data(pid, (void*) plm, &lm, sizeof(lm))) != 0)
			return 0;
		pEhdr = lm.l_addr;
	}

	if ((ret = read_data(pid, pEhdr, &ehdr, sizeof(ehdr))) != 0) {
		ALOGE("%s: read ehdr failed\n", __FUNCTION__);
		return 0;
	}

	for (i = 0, pShdr = (ElfW(Shdr)*) ((char*) pEhdr + ehdr.e_shoff); i < ehdr.e_shnum; i++, pShdr++) {
		if ((ret = read_data(pid, (void*)pShdr, &shdr, sizeof(shdr))) != 0) {
			ALOGE("%s: read shdr failed\n", __FUNCTION__);
			return 0;
		}

		if (shdr.sh_type == SHT_DYNSYM) {
			return shdr.sh_size / shdr.sh_entsize;
		}
	}

	return 0;
}*/


// TODO the first LOAD segment's vaddr. see phdr
unsigned long* image_start_addr(pid_t pid) {
#if defined(LINUX)
#if __WORDSIZE == 64
	return (unsigned long*)0x0000000000400000;
#else
	return (unsigned long*)0x08048000;
#endif
#elif defined(ANDROID)
    unsigned long value;
    get_module_base(pid, NULL, &value);
    return (unsigned long*)value;
#endif


}

#if !defined(ANDROID)
int get_linkmap(pid_t pid, unsigned long *value) {
	int ret = -1;
	struct link_map* plm = NULL;
	ElfW(Ehdr) *pEhdr, ehdr;
	ElfW(Phdr) *pPhdr, phdr;
	ElfW(Dyn)  *pDyn, dyn;

	long* pGot;

	if (value == NULL)
		return -EINVAL;

	int i = 0;
	if (pid > 0) {
		pEhdr = (ElfW(Ehdr)*) image_start_addr(pid);
		if ((ret = read_data(pid, pEhdr, &ehdr, sizeof(ehdr))) != 0) {
			return ret;
		}

		// find .dynamic
		pDyn = NULL;

		for (i = 0, pPhdr = (ElfW(Phdr)*) ((char*) pEhdr + ehdr.e_phoff); i < ehdr.e_phnum; i++, pPhdr++) {

			if ((ret = read_data(pid, pPhdr, &phdr, sizeof(phdr))) != 0) {
				//ALOGE("");
				return ret;
			}

			if (phdr.p_type == PT_DYNAMIC) {
				pDyn = (ElfW(Dyn)*)phdr.p_vaddr;
				break;
			}
		}

		if (pDyn == NULL) {
			return -1;
		}

		if ((ret = read_data(pid, pDyn, &dyn, sizeof(dyn))) != 0) {
			return ret;
		}

		pGot = NULL;
		// find sections
		while (dyn.d_tag != DT_NULL) {
			switch (dyn.d_tag) {
			default:
				break;
			case DT_PLTGOT:
				pGot = (long*)dyn.d_un.d_ptr;
				break;
			}

			pDyn++;
			if ((ret = read_data(pid, pDyn, &dyn, sizeof(dyn))) != 0) {
				return ret;
			}
		}

		if (pGot != NULL) {
			if ((ret = read_data(pid, pGot + 1, &plm, sizeof(plm))) != 0) {
				return ret;
			} else {
				*value = (unsigned long)plm;
				ret = 0;
			}
		}

	} else {
		plm = dlopen(NULL, RTLD_LAZY);
		*value = (unsigned long)plm;
		ret = 0;
	}

	return ret;
}

int find_func_in_link(pid_t pid, const struct link_map* plm, const char* name, unsigned long *value) {

	int ret = -1;
	ElfW(Dyn) *pDyn, dyn;
	ElfW(Sym) *pSym, sym;
	const char* pStrTable;

	unsigned int *pInt;
	int nChains = 0;
	int i;
	char* pBuf;
	struct link_map lm;
	hash_state_t *p_hash_stat = NULL;
	int bytescount = 0;

	int use_hash = 0; // 0: not use hash, 1: use hash, 2: use gnu_hash;

	if (plm == NULL || value == NULL)
		return -EINVAL;

	if ((ret = read_data(pid, (void*)plm, &lm, sizeof(lm))) != 0)
		return ret;

	pBuf = ptrace_get_str(pid, lm.l_name);
	if (pBuf != NULL) {
		ALOGE("%s: find func in %s\n", __FUNCTION__, pBuf);
		free(pBuf);
		pBuf = NULL;
	}

	// link map->dynamic->symbol-> base + offset
	pDyn = lm.l_ld;
	if ((ret = read_data(pid, pDyn, &dyn, sizeof(dyn))) != 0)
		return ret;

	pStrTable = NULL;
	pSym = NULL;
	int index = 0;
	while (dyn.d_tag != DT_NULL) {
		switch (dyn.d_tag) {
		default:
			break;
		case DT_SYMTAB:
			pSym = (ElfW(Sym)*)dyn.d_un.d_ptr;
			break;
		case DT_STRTAB:
			pStrTable = (char*)dyn.d_un.d_ptr;
			break;
		case DT_HASH: // TODO this section may not existed!! find the count of .dynsym
			if (use_hash != 2)
				use_hash = 1;
			pInt = (int*)(dyn.d_un.d_ptr);
			if ((ret = read_data(pid, pInt + 1, &nChains, sizeof(nChains))) != 0)
				return ret;
			break;
		case DT_GNU_HASH:
			use_hash = 2;
			pInt = (int*)(dyn.d_un.d_ptr);
			p_hash_stat = malloc(sizeof(hash_state_t));
			memset(p_hash_stat, 0, sizeof(hash_state_t));
			p_hash_stat->base = lm.l_addr;

			// read gnu hash content
			if ((ret = read_data(pid, pInt++, &(p_hash_stat->nbuckets), sizeof(int))) != 0) goto error;
			if ((ret = read_data(pid, pInt++, &(p_hash_stat->symndx), sizeof(int))) != 0) goto error;
			if ((ret = read_data(pid, pInt++, &(p_hash_stat->maskwords_bm), sizeof(int))) != 0) goto error;

			if ((ret = read_data(pid, pInt++, &(p_hash_stat->shift2), sizeof(int))) != 0) goto error;

			bytescount = sizeof(long) * p_hash_stat->maskwords_bm;
			p_hash_stat->pbloom = malloc(bytescount);
			if ((ret = read_data(pid, pInt, (void*)p_hash_stat->pbloom, bytescount)) != 0) goto error;
			pInt += bytescount / sizeof(int);

			bytescount = sizeof(int) * p_hash_stat->nbuckets;
			p_hash_stat->pbuckets = malloc(bytescount);
			if ((ret = read_data(pid, pInt, (void*)p_hash_stat->pbuckets, bytescount)) != 0) goto error;
			pInt += p_hash_stat->nbuckets;

			p_hash_stat->phashval = pInt;
			/*int dynsymcount = getDynsymCount(pid, plm);
			ALOGE("%s: dynsym count %d\n", __FUNCTION__, dynsymcount);
			if (dynsymcount <= p_hash_stat->symndx) {
				goto error;
			}

			bytescount = sizeof(int) * (dynsymcount - p_hash_stat->symndx);
			p_hash_stat->phashval = malloc(bytescount);
			if ((ret = read_data(pid, pInt, (void*)p_hash_stat->phashval, bytescount)) != 0) goto error;
			*/
			break;
		}
		index++;
		pDyn++;
		if ((ret = read_data(pid, pDyn, &dyn, sizeof(dyn))) != 0) {
			goto error;
		}
	}

	if (pSym == NULL || pStrTable == NULL)
		goto error;


	if (use_hash == 0)
		nChains = 0;

	switch (use_hash) {
	default:
		break;
	case 0:
	case 1:
		for (i = 1; i < nChains; i++) {

			if ((ret = read_data(pid, pSym + i, &sym, sizeof(sym))) != 0)
				return ret;

			if (pid == 0) {
				if (*(pStrTable + sym.st_name) != '\0'
						&& strcmp(name, pStrTable + sym.st_name) == 0) {
					*value = sym.st_value + lm.l_addr;
					ret = 0;
				}
			} else {
				pBuf = ptrace_get_str(pid, (const long*) (pStrTable + sym.st_name));
				if (pBuf != NULL) {
					if (pBuf[0] != '\0' && strcmp(name, pBuf) == 0) {
						free(pBuf);
						*value = sym.st_value + lm.l_addr;
						return 0;
					}
					free(pBuf);
				}
			}

		}
	break;
	case 2:
		if (p_hash_stat != NULL) {
			p_hash_stat->pdynsym = pSym;
			p_hash_stat->pdynstr = pStrTable;
			ret = find_sym_by_hash(pid, p_hash_stat, name, value);
			free_hash_state(p_hash_stat);

			return ret;
		}
		break;
	}

	return -1;

error:
	free_hash_state(p_hash_stat);
	return -1;
}
#endif

// if (not lazy bind || already referenced)
int find_func_by_got(pid_t pid, const char* name, unsigned long* entry_addr, unsigned long* entry_value) {
	volatile int ret = -1;
	volatile ElfW(Ehdr) *pEhdr = NULL, ehdr;
	volatile ElfW(Phdr) *pPhdr = NULL, phdr;
	volatile ElfW(Dyn)  *pDyn = NULL, dyn;
	char* image_base = NULL;
#if defined(ANDROID)
	volatile ElfW(Rel) *pRel = NULL, rel;
#else
	ElfW(REL_TYPE) *pRel = NULL, rel;
#endif
	volatile ElfW(Sym) *pSym = NULL, sym;
	char*	pStrTable;

	long totalRelaSize, relEnt = sizeof(rel);
	char* pBuf;
	int i;

	if (entry_addr == NULL && entry_value == NULL)
		return -EINVAL;

	// ehdr->phdr->dynamic->rela->sym: name@symbol and vaddr@offset
	// rela has the name index in sym and the vaddr of the .got.plt entry

	image_base = (char*)image_start_addr(pid);


	pEhdr = (ElfW(Ehdr)*)image_base;

	if ((ret = read_data(pid, pEhdr, &ehdr, sizeof(ehdr))) != 0) {
		ALOGE("%s: read ehdr failed\n", __FUNCTION__);
		return ret;
	}

	// find .dynamic
	pDyn = NULL;

	for (i = 0, pPhdr = (ElfW(Phdr)*) ((char*) pEhdr + ehdr.e_phoff); i < ehdr.e_phnum; i++, pPhdr++) {

		if ((ret = read_data(pid, pPhdr, &phdr, sizeof(phdr))) != 0) {
			ALOGE("%s: read phdr failed\n", __FUNCTION__);
			return ret;
		}

		if (phdr.p_type == PT_DYNAMIC) {
#if defined(ANDROID)
			pDyn = (ElfW(Dyn)*) (image_base + phdr.p_vaddr);
#else
			pDyn = (ElfW(Dyn)*) (phdr.p_vaddr);
#endif
			break;
		}
	}

	if (pDyn == NULL) {
		return -1;
	}

	if ((ret = read_data(pid, pDyn, &dyn, sizeof(dyn))) != 0) {
		return ret;
	}

	// find dynamic sections
	while (dyn.d_tag != DT_NULL) {
		switch (dyn.d_tag) {
		default:
			break;
		case DT_JMPREL:  // address of PLT
#if defined(ANDROID)
			pRel = (ElfW(Rel)*)(image_base + dyn.d_un.d_ptr);
#else
			pRel = (ElfW(REL_TYPE)*)dyn.d_un.d_ptr;
#endif

			break;
		case DT_PLTRELSZ:
			totalRelaSize = dyn.d_un.d_val;
			break;
		/*case DT_RELAENT:
			relaEnt = dyn.d_un.d_val;
			break;*/
		case DT_SYMTAB: // address of symbol table
#if defined(ANDROID)
			pSym = (ElfW(Sym)*)(image_base + dyn.d_un.d_ptr);
#else
			pSym = (ElfW(Sym)*)dyn.d_un.d_ptr;
#endif
			break;
		case DT_STRTAB: // address of string table
#if defined(ANDROID)
			pStrTable = (char*)(image_base + dyn.d_un.d_ptr);
#else
			pStrTable = (char*)dyn.d_un.d_ptr;
#endif
			break;

		}

		pDyn++;
		if ((ret = read_data(pid, pDyn, &dyn, sizeof(dyn))) != 0) {
			return ret;
		}
	}

	if (pRel == NULL || pSym == NULL || pStrTable == NULL) {
		ALOGE("%s: cannot find dynamic sections\n", __FUNCTION__);
		return -1;
	}

	if (totalRelaSize == 0) {
		ALOGE("%s: total rela size is 0\n", __FUNCTION__);
		return -1;
	}

	if (relEnt == 0) {
		ALOGW("%s: cannot find rela entry size, set to %d\n", __FUNCTION__, sizeof(rel));
		relEnt = sizeof(rel);
	}

	for (i = 0; i < totalRelaSize / relEnt; i++, pRel++) {
		// read a rela entry
		if ((ret = read_data(pid, pRel, &rel, sizeof(rel))) != 0) {
			return ret;
		}

		// read a symbol in sym table
#if defined(ANDROID)
		ret = read_data(pid, pSym + ELF32_R_SYM(rel.r_info),&sym, sizeof(sym));
#else
		ret = read_data(pid, pSym + ELFW_R(SYM)(rel.r_info),&sym, sizeof(sym));
#endif
		if (ret != 0) {
			ALOGE("%s read rel entry %d failed\n", __FUNCTION__, i);
			return ret;
		}

		if (pid == 0) {
			if (strcmp(name, pStrTable + sym.st_name) == 0) {
				if (entry_addr != NULL)
					*entry_addr = rel.r_offset;
				if (entry_value != NULL)
					*entry_value = *((long*)rel.r_offset);
			}
		} else {
			pBuf = ptrace_get_str(pid, (const long*)(pStrTable + sym.st_name));
			if (pBuf != NULL) {
				if (pBuf[0] != '\0' && strcmp(name, pBuf) == 0) {
					free(pBuf);
					ret = 0;
					if (entry_addr != NULL)
#if defined (ANDROID)
						*entry_addr = image_base + rel.r_offset;
#else
						*entry_addr = rel.r_offset;
#endif
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

#if !defined(ANDROID)
// if module_name is null, search each module
int find_func_by_links(pid_t pid, const struct link_map* plm, const char* name, const char* module_name, unsigned long *value) {
	char* pStr = NULL;
	struct link_map lm;
	int ret = -1;

	if (plm == NULL || name == NULL || value == NULL)
		return -EINVAL;

	if (module_name != NULL) {
		while(plm != NULL) {
			read_data(pid, plm, &lm, sizeof(lm));
			pStr = ptrace_get_str(pid, (const long*)lm.l_name);
			if (pStr != NULL) {
				if (strcmp(pStr, name) == 0)
					break;
				free(pStr);
			}
			plm = lm.l_next;
		}

		if (pStr != NULL) {
			free(pStr);
			pStr = NULL;
		}

		return plm != NULL ? find_func_in_link(pid, plm, name, value) : -1;

	} else {
		for (; plm != NULL; plm = lm.l_next) {
			if ((ret = read_data(pid, plm, &lm, sizeof(lm))) != 0)
				return ret;

			if (ptrace_strlen(pid, (const long*) lm.l_name) > 0) {
				if (find_func_in_link(pid, plm, name, value) == 0)
					return 0;
			}
		}
	}

	return -1;

}
#endif

static int find_name_by_pid(pid_t pid, char* buf, size_t size) {

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

int get_module_base(pid_t pid, const char* module_name, unsigned long* value) {

	FILE *fin = NULL;
	char path[256] = { 0 }, line[1024] = { 0 }, selfname[1024] = {0};
	long addr = 0;
	char*pch;
	int ret = -1;

	if (module_name == NULL) {
	    if (find_name_by_pid(pid, selfname, 1024) != 0) {
            ALOGE("find name by pid %d failed %d\n", pid, errno);
            return errno;
        }
    }

	if (pid <= 0)
		snprintf(path, sizeof(path), "/proc/self/maps");
	else
		snprintf(path, sizeof(path), "/proc/%d/maps", pid);

	if ((fin = fopen(path, "r")) == NULL)
		return errno;

	while (fgets(line, sizeof(line), fin) != NULL) {
		if (strstr(line, module_name == NULL ? selfname : module_name) != NULL) {
			pch = strtok(line, "-");
			addr = strtoul(pch, NULL, 16);
			if (value != NULL)
				*value = addr;
			ret = 0;
			break;
		}
		memset(line, 0, sizeof(line));
	}

	fclose(fin);

	return ret;
}

int find_pid_of(const char*process_name) {
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

	while ((entry = readdir(dir)) != NULL) {
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

#if 0
int find_func_by_module_base(pid_t pid, const char* name, const char* module_name, const unsigned long* local_addr, unsigned long *value) {

	if (module_name == NULL || local_addr == NULL)
		return -EINVAL;

	void *local_base, *remote_base;

	local_base = get_module_base(0, module_name);
	remote_base = get_module_base(target_pid, module_name);

	void * ret_addr = (void*)((unsigned long)local_addr + (unsigned long)remote_handle - (unsigned long)local_handle);

	if (value != NULL)
		*value = ret_addr;

	return 0;
}
#endif

