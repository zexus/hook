/************************************************************************
xxx
All rights reserved.

File Name:
Summary:
Current Version:
Author:

History:
Ver 1.0.0, xxx, 2015.03.24
Add “switch windows” function for recording

Ver 0.0.0, xxx, 2015.03.24
Original version

**************************************************************************/
#include <stdio.h>    
#include <stdlib.h>    
#include <stdbool.h>
#if defined(LINUX)
#include <sys/user.h>
#include <sys/ptrace.h>
#include <link.h>
#include <sys/reg.h>
#elif defined(ANDROID)
#include <sys/user.h>
#include <asm/ptrace.h>
#else
#endif
#include <sys/wait.h>    
#include <sys/mman.h>    
#include <dlfcn.h>
#include <unistd.h>    
#include <string.h>    
#include <errno.h>
#include <elf.h>    

#include "log.h"

#if defined(LINUX)

//__attribute__((weak)) void *dlopen (__const uint8_t*, int);
//__attribute__((weak)) void *dlsym (void *__restrict , __const uint8_t*__restrict);
//__attribute__((weak)) int dlclose (void *);
//__attribute__((weak)) uint8_t*dlerror (void);

#endif    

#include "elf_util.h"
#include "ptrace_util.h"

#define CPSR_T_MASK     ( 1u << 5 )    

// TODO these paths are from /proc
// linker can be got from .interp and libc from .dynamic

static char* slibpath;

static bool is_injected(pid_t pid, const char* module_name) {
	if (module_name == NULL)
		return false;

	FILE *fin = NULL;
	char path[256] = { 0 }, line[1024] = { 0 };
	bool ret = false;

	snprintf(path, sizeof(path), "/proc/%d/maps", pid);
	if ((fin = fopen(path, "r")) == NULL)
		return ret;
	while (fgets(line, sizeof(line), fin) != NULL) {
		if (strstr(line, module_name) != NULL) {
			ret = true;
			break;
		}
		memset(line, 0, sizeof(line));
	}

	fclose(fin);
	return ret;
}

static int Hookusage() {
	fprintf(stderr, "Usage: hook pname | -n pid\n");
	return EINVAL;
}

int HookTest(pid_t nTargetPid) {
	int nRet = 0;
	int i = 0;
	uint8_t *map_base = 0;
	void *mmap_addr, *dlopen_addr, *dlsym_addr, *dlclose_addr, *dlerror_addr;

	if (nTargetPid < 0) {
		printf("Invalid process pid: %d\n", nTargetPid);
		return -1;
	}

	nRet = ptrace_attach(nTargetPid);
	if (0 != nRet) {
		printf("attach %d failed %d %s\n", nTargetPid, nRet, strerror(nRet));
		return -1;
	}

	unsigned long addr, value;
	const char* tofind = "Hook_Entry_Test";

	nRet = find_func_by_got(nTargetPid, tofind, &addr, &value);

	ALOGI("%s found by got addr: 0x%lx entry: 0x%lx\n", tofind, value, addr);

	#if !defined(ANDROID)
	struct link_map* plm;
	value = 0;
	get_linkmap(nTargetPid, &value);
	plm = (struct link_map*)value;
	nRet = find_func_by_links(nTargetPid, plm, tofind, NULL, &value);
	ALOGI("find_func_by_links: %s found at 0x%lx\n", tofind, value);
	#endif

	struct pt_regs origin_regs;
	ptrace_get_regs(nTargetPid, &origin_regs);

	if (0 == nRet) {
		call_param_t param[7];

		dlopen_addr = find_func_by_module_base(nTargetPid, LINKER_PATH, (void *)dlopen );
		dlsym_addr = find_func_by_module_base(nTargetPid, LINKER_PATH, (void *)dlsym );
		dlclose_addr = find_func_by_module_base(nTargetPid, LINKER_PATH, (void *)dlclose );
		dlerror_addr = find_func_by_module_base(nTargetPid, LINKER_PATH, (void *)dlerror );

		ALOGI("[+] Get imports: dlopen: 0x%lx, dlsym: 0x%lx, dlclose: 0x%lx, dlerror: 0x%lx\n", dlopen_addr, dlsym_addr, dlclose_addr, dlerror_addr);

		/* call dlopen */
		param[0].value = "/system/lib/libhook.so";
		param[0].size = strlen((char*) (param[0].value)) + 1;
		#ifndef PARAM_ONLY_BY_STACK
		param[0].index = 0;
		#endif
		param[0].type = CALL_PARAM_TYPE_POINTER;

		param[1].value = RTLD_NOW | RTLD_GLOBAL;
		#ifndef PARAM_ONLY_BY_STACK
		param[1].index = 1;
		#endif
		param[1].type = CALL_PARAM_TYPE_CONSTANT;

		unsigned long sohandle;

		nRet = ptrace_call(nTargetPid, dlopen_addr, param, 2, &sohandle);

		if (0x0 == sohandle) {
			ALOGE("[+] call dlopen error\n");
			nRet =  -1;
			goto exit;
		} else {
			ALOGI("[+] so_handle: %p\n", sohandle);
		}

		/* call dlsym */
		param[0].value = sohandle;

		#ifndef PARAM_ONLY_BY_STACK
		param[0].index = 0;
		#endif

		param[0].type = CALL_PARAM_TYPE_CONSTANT;

		param[1].value = "hook_entry_test";

		#ifndef PARAM_ONLY_BY_STACK
		param[1].index = 1;
		#endif

		param[1].type = CALL_PARAM_TYPE_POINTER;
		param[1].size = strlen((char*)param[1].value) + 1;

		unsigned long hook_entry_addr;

		nRet = ptrace_call(nTargetPid, dlsym_addr, param, 2, &hook_entry_addr);

		if (0x0 == hook_entry_addr) {
			ALOGE("[+] call dlsym error\n");
			nRet = -1;
			goto exit;
		} else {
			ALOGI("[+] hook entry address = %p\n", hook_entry_addr);
		}

		for (i = 1; i < 7; i++) {
			param[i].value = i;

			#ifndef PARAM_ONLY_BY_STACK
			param[i].index = i;
			#endif

			param[i].type = CALL_PARAM_TYPE_CONSTANT;
		}

		param[0].value = "Hooking";
		#ifndef PARAM_ONLY_BY_STACK
		param[0].index = 0;
		#endif
		param[0].size = strlen((char*)param[0].value) + 1;
		param[0].type = CALL_PARAM_TYPE_POINTER;

		nRet = ptrace_call(nTargetPid, hook_entry_addr, param, 7, NULL);

		printf("Press enter to dlclose and detach\n");
		getchar();
		ALOGI("ptrace_call ret %d\n", nRet);
	}
	else
		ALOGE("function %s not found %d\n", tofind, nRet);

exit:
	if (0 != nRet) {
		ALOGE("EXIT EXCEPTION\n");
	} else {
		ALOGE("EXIT NORMAL\n");
	}

	ptrace_set_regs(nTargetPid, &origin_regs);

	if (nTargetPid > 0)
		ptrace_detach(nTargetPid);

	return nRet;
}

/**
 @brief 动态库注入主函数
 @param[in] 指定将要注入的进程pid，如：<processname> -n <pid>
 @return 成功注入返回0, 失败返回－1
 @note 后续将主函数入口添加参数，以动态库形式供其它程序调用
**/
int main(int argc, char** argv) {
	pid_t nTargetPid = -1;
	const char* pName = NULL;
	const char* libPath = NULL;
	const char* funcName = NULL;
	const char* params = NULL;

	char* end = NULL;
	int index = 1;

	void* handle = NULL;
	void* addr;
	struct pt_regs regs, original_regs;
	struct link_map* lm;
	long parameters[5];

	if (argc < 2)
		return Hookusage();

	if (argv[1][0] == '-' && argv[1][1] == 'n') {
		nTargetPid = strtol(argv[2], &end, 10);
		if (strlen(end) > 0) {
			fprintf(stderr, "invalid pid %s\n", argv[2]);
			return EINVAL;
		}
		index += 2;
	} else {
		pName = argv[index++];
	}

	if (nTargetPid < 0) {
		nTargetPid = find_pid_of(pName);
		if (-1 == nTargetPid) {
			ALOGE("Can't find the process %s\n", pName);
			return -1;
		}
	}

	// if (is_injected(nTargetPid, libPath)) {
	// 	ALOGD("Process(%d) already injected %s !", nTargetPid, libPath);
	// 	return 0;
	// }

	// slibpath = libPath;

	HookTest(nTargetPid);

	return 0;
}
