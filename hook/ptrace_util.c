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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/mman.h>
#if defined(LINUX)
#include <sys/reg.h>
#elif defined(ANDROID)
#include <asm/signal.h>
#endif
#include <errno.h>
#include "ptrace_util.h"
#include "log.h"

#pragma GCC diagnostic ignored "-Wformat"

//static int ptrace_wait_signal(pid_t pid, int sig);
// static int ptrace_pass_param(pid_t pid, const call_param_t *param);

extern char* strsignal(int);

#if defined(ANDROID)
#define CPSR_T_MASK     (1u << 5)
#endif

typedef union {
	long value;
	char chars[sizeof(long)];
}WORDUN;

static void* sMapBase = NULL;
static long sOffset = 0;

static void* requestMemoryForPassParam(pid_t pid, int len);
static int ptrace_pass_param(pid_t pid, const call_param_t *params, int num_params, long *sp);

int ptrace_attach(pid_t nTargetPid) {
	int nRet = 0;
	int nStatus = 0;

	nRet = ptrace(PTRACE_ATTACH, nTargetPid, NULL, NULL);
	if (0 != nRet) {
		return errno;
	}

	waitpid(nTargetPid, &nStatus, WUNTRACED);
	return 0;
}

int ptrace_detach(pid_t pid){
	return ptrace(PTRACE_DETACH, pid, NULL, NULL) != 0 ? errno : 0;
}

int ptrace_continue(pid_t pid) {
	return ptrace(PTRACE_CONT, pid, NULL, NULL) != 0 ? errno : 0;
}

int ptrace_syscall(pid_t pid) {
	return ptrace(PTRACE_SYSCALL, pid, NULL, NULL) != 0 ? errno : 0;
}

int ptrace_get_reg(pid_t pid, int index, long* out) {
	errno = 0;

	if (out != NULL) {
		#if defined(ANDROID)
		struct pt_regs regs;

		if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) != 0) {
			return errno;
		} else {
			if (out != NULL)
				*out = regs.uregs[index];
			return 0;
		}
		#else
		*out = ptrace(PTRACE_PEEKUSER, pid, index * sizeof(long), out, NULL);
		return errno;
		#endif
	} else {
		return EINVAL;
	}
}

int ptrace_set_reg(pid_t pid, int index, long value) {
	return ptrace(PTRACE_POKEUSER, pid, index * sizeof(long), &value) != 0 ? errno : 0;
}

/**
 @brief 获取各寄存器数值
 @param[in] 指定进程pid
 @param[in] 将存入数值的pt_regs结构体
 @return 成功获取返回0, 失败返回错误代码
 @note 获取到的数值存入pt_regs结构体
**/
int ptrace_get_regs(pid_t pid, struct pt_regs * regs) {
	if (regs != NULL) {
		return ptrace(PTRACE_GETREGS, pid, NULL, regs) != 0 ? errno : 0;
	} else
		return EINVAL;
}

/**
 @brief 设置各寄存器数值
 @param[in] 指定进程pid
 @param[in] 将设置数值的pt_regs结构体
 @return 成功获取返回0, 失败返回错误代码
 @note 设置pt_regs结构体各数值存入各寄存器
**/
int ptrace_set_regs(pid_t pid, const struct pt_regs * regs) {
	if (regs == NULL)
		return EINVAL;
	else
		return ptrace(PTRACE_SETREGS, pid, NULL, regs) != 0 ? errno : 0;
}

int ptrace_read_bytes(pid_t pid, const unsigned long *src, void *buf, size_t size) {
	int wordCount, byteRemain;
	const unsigned long *srcAddr;
	long *dstAddr;
	WORDUN un;
	int i;

	if (src == NULL || buf == NULL || size < 0)
		return EINVAL;

	wordCount = size / sizeof(long);
	byteRemain = size % sizeof(long);
	srcAddr = src;
	dstAddr = buf;

	for (i = 0; i < wordCount; i++, srcAddr++, dstAddr++) {
		errno = 0;
		*(dstAddr) = ptrace(PTRACE_PEEKDATA, pid, srcAddr, NULL);
		if (errno != 0) {
			ALOGE("PEEKDATA from addr 0x%lx failed %d %s\n", srcAddr, errno, strerror(errno));
			return errno;
		}
	}


	if (byteRemain > 0) {
		errno = 0;
		un.value = ptrace(PTRACE_PEEKDATA, pid, srcAddr, NULL);
		if (errno != 0) {
			ALOGE("PEEKDATA from addr 0x%lx failed %d %s\n", srcAddr, errno, strerror(errno));
			return errno;
		}
		for (i = 0; i < byteRemain; i++)
			((char*)dstAddr)[i] = un.chars[i];
	}

	return 0;
}

int ptrace_write_bytes(pid_t pid, unsigned long *dst, const void *buf, size_t size) {

	int wordCount, byteRemain;
	unsigned long *dstAddr;
	const long *dataAddr;
	WORDUN un;
	int i;

	if (dst == NULL || buf == NULL || size < 0)
		return EINVAL;

	wordCount = size / sizeof(long);
	byteRemain = size % sizeof(long);
	dstAddr = dst;
	dataAddr = buf;

	for (i = 0; i < wordCount; i++, dstAddr++, dataAddr++)
		if (ptrace(PTRACE_POKEDATA, pid, dstAddr, (void*) (*dataAddr)) != 0) {
			printf("POKEDATA to 0x%lx failed %d\n", dstAddr, errno);
			return errno;
		}

	if (byteRemain > 0) {
		un.value = ptrace(PTRACE_PEEKDATA, pid, dstAddr, NULL);
		if (errno != 0) {
			printf("PEEKDATA in write bytes failed %d\n", errno);
			return errno;
		}
		for (i = 0; i < byteRemain; i++)
			un.chars[i] = ((char*) dataAddr)[i];
		if (ptrace(PTRACE_POKEDATA, pid, dstAddr, (void*) (un.value)) != 0) {
			printf("POKEDATA 0x%lx failed %d\n", dstAddr, errno);
			return errno;
		}
	}

	return 0;
}

int ptrace_push_bytes(pid_t pid, const void *buf, size_t size, unsigned long* sp) {
	int ret;
	if (buf != NULL) {
		struct pt_regs regs;
		ptrace_get_regs(pid, &regs);
		int len = ((size + sizeof(long) - 1) / sizeof(long)) * sizeof(long);

		long currentSp = regs.REG_SP - len;
		/*if ((ret = ptrace_get_reg(pid, REG_SP_INDEX, &currentSp)) != 0)
			return ret;
		currentSp -= len;
		if ((ret = ptrace_set_reg(pid, REG_SP_INDEX, currentSp)) != 0)
			return ret;
		*/
		if ((ret = ptrace_write_bytes(pid, (unsigned long*)currentSp, buf, len)) != 0)
			return ret;

		regs.REG_SP = currentSp;
		ptrace_set_regs(pid, &regs);
		if (sp != NULL)
			*sp = currentSp;
	} else
		return EINVAL;

	return 0;
}

int ptrace_push(pid_t pid, long value, unsigned long* sp) {
	return ptrace_push_bytes(pid, &value, sizeof(value), sp);
}

int ptrace_strlen(pid_t pid, const unsigned long *addr) {
	int len = 0;
	int i;
	WORDUN un;

	if (pid > 0) {
		while (1) {
			un.value = ptrace(PTRACE_PEEKDATA, pid, addr, 0);
			for (i = 0; i < sizeof(long); i++) {
				if (un.chars[i] != '\0')
					len++;
				else
					return len;
			}
			addr++;
		}
	} else {
		len = strlen((const char*) addr);
	}

	return len;
}

int ptrace_read_str(pid_t pid, const unsigned long *addr, void* buf, size_t size) {
	int strLen = 0;
	int ret = 0;

	if (addr == NULL || buf == NULL || size < 0)
		return EINVAL;

	strLen = ptrace_strlen(pid, addr);
	strLen = strLen <= size ? strLen : size;

	if (strLen > 0) {
		ret = ptrace_read_bytes(pid, addr, buf, strLen);
		if (strLen < size)
			((char*)buf)[strLen] = '\0';
	}

	return ret;
}

char* ptrace_get_str(pid_t pid, const unsigned long *addr) {
	char* result = NULL;
	int strLen = 0;
	// int ret = 0;

	if (addr == NULL)
		return NULL;

	strLen = ptrace_strlen(pid, addr);

	if (strLen > 0) {
		result = malloc(strLen + 1);
		ptrace_read_bytes(pid, addr, result, strLen);
		result[strLen] = '\0';
	}

	return result;
}

int ptrace_call(pid_t pid, unsigned long addr, const call_param_t *params, int num_params, long* retVal) {
	// int ret = -1;
	sOffset = 0;
	// pass parameters
	long value;
	int i;
	struct pt_regs regs;

	ptrace_pass_param(pid, params, num_params, &value);

	#if !defined(ANDROID)
	ptrace_push(pid, 0x00, &value);
	#endif

	ptrace_get_regs(pid, &regs);

	int offset = 0;

	#if defined (LINUX)
	offset = ptrace_is_remote_interrupted_in_syscall(pid) ? 2 : 0;
	#endif

	regs.REG_IP = addr + offset;

	#if defined(ANDROID)
	if (regs.ARM_pc & 1) {
		// thumb
		regs.ARM_pc &= (~1u);
		regs.ARM_cpsr |= CPSR_T_MASK;
	} else {
		// arm
		regs.ARM_cpsr &= ~CPSR_T_MASK;
	}

	regs.ARM_lr = 0;
	#endif

	int ret = ptrace_set_regs(pid, &regs);if (ret != 0)ALOGE("error line %d\n", __LINE__);
	ret = ptrace_continue(pid);if (ret != 0)ALOGE("error line %d\n", __LINE__);
	ret = ptrace_wait_signal(pid, SIGSEGV);if (ret != 0)ALOGE("error line %d\n", __LINE__);

	if (retVal != NULL) {
		 ptrace_get_reg(pid, REG_AX_INDEX, retVal);
	}

	return 0;
}

int ptrace_wait_signal(pid_t pid, int sig) {
	int status;
	int wsig;

	if (pid <= 0 || waitpid(pid, &status, WUNTRACED) != pid || !WIFSTOPPED (status))
		return -1;

	wsig = WSTOPSIG(status);
	if (wsig != sig) {
		ALOGW("%s: expected signal %d but got %d status 0x%x: \"%s\"\n", __FUNCTION__, sig, wsig, status, (const char*)strsignal(wsig));
		return wsig;
	} else {
		ALOGI("got sig %d from pid %d\n", sig, pid);
		return 0;
	}

	return 0;
}

static int ptrace_pass_param(pid_t pid, const call_param_t *params, int num_params, long *sp) {
	int ret = EINVAL;
	int i, j;
	long value;

	if (pid <= 0 || params == NULL)
		return ret;

	if (num_params <= 0)
		return 0;

	call_param_t param;

	#if !(defined (LINUX) && __WORDSIZE == 32)
	struct pt_regs regs;
	ptrace_get_regs(pid, &regs);

	for (i = 0; i < num_params && i < REG_PASS_PARAM_NUM; i++) {
		long param_value = 0;
		void* remote_addr;
		param = params[i];

		if (param.type == CALL_PARAM_TYPE_POINTER) {
			remote_addr = requestMemoryForPassParam(pid, param.size);
			if (remote_addr == NULL) {
				ALOGE("error: request memory failed\n");
				return -1;
			}
			ret = ptrace_write_bytes(pid, remote_addr, param.value, param.size);
			if (ret != 0) {
				ALOGE("error: write remote memory failed\n");
				return ret;
			}
			param_value = remote_addr;
		} else {
			param_value = param.value;
		}

        
		switch (param.index) {
		default:
			break;
		case 0:
			regs.REG_PASS_PARAM(0) = param_value;
			break;
		case 1:
			regs.REG_PASS_PARAM(1) = param_value;
			break;
		case 2:
			regs.REG_PASS_PARAM(2) = param_value;
			break;
		case 3:
			regs.REG_PASS_PARAM(3) = param_value;
			break;
#if !defined (ANDROID)
		case 4:
			regs.REG_PASS_PARAM(4) = param_value;
			break;
		case 5:
			regs.REG_PASS_PARAM(5) = param_value;
			break;
#endif
		}
	}




	for (j = num_params - 1; j >=i; --j) {
		// reg_index = -1;
		long param_value = 0;
		void* remote_addr;
		param = params[j];

		if (param.type == CALL_PARAM_TYPE_POINTER) {
			remote_addr = requestMemoryForPassParam(pid, param.size);
			if (remote_addr == NULL) {
				ALOGE("error: request memory failed\n");
				return -1;
			}
			ret = ptrace_write_bytes(pid, remote_addr, param.value, param.size);
			if (ret != 0) {
				ALOGE("error: write remote memory failed\n");
				return ret;
			}
			param_value = remote_addr;
		} else {
			param_value = param.value;
		}

		ptrace_push(pid, param_value, NULL);
	}

	ret = ptrace_get_reg(pid, REG_SP_INDEX, &(regs.REG_SP));if (ret != 0)ALOGE("get sp failed %d\n", ret);
	ret = ptrace_set_regs(pid, &regs);if (ret != 0)ALOGE("error line %d\n", __LINE__);

	if (sp != NULL)
		*sp = regs.REG_SP;
#else
#error "TODO"

	for (i = num_params - 1; i >=0; --j) {

		long param_value = 0;
		void* remote_addr;
		param = params[i];

		if (param.type == CALL_PARAM_TYPE_POINTER) {
			remote_addr = requestMemoryForPassParam(pid, param.size);
			if (remote_addr == NULL) {
				ALOGE("error: request memory failed\n");
				return -1;
			}
			ret = ptrace_write_bytes(pid, remote_addr, param.value, param.size);
			if (ret != 0) {
				ALOGE("error: write remote memory failed\n");
				return ret;
			}
			param_value = remote_addr;
		} else {
			param_value = param.value;
		}

		ptrace_push(pid, param_value, sp);
	}

#endif
	return ret;
}

static void* requestMemoryForPassParam(pid_t pid, int len) {
	int ret = 0;
	void *addr;
    int i = 0;
	if (sMapBase == NULL) {
		call_param_t parameters[6];
		for (i = 0; i < 6; ++i) {
#ifndef PARAM_ONLY_BY_STACK
			parameters[i].index = i;
#endif
			parameters[i].type = CALL_PARAM_TYPE_CONSTANT;
		}
		parameters[0].value = 0; // addr
		parameters[1].value = 0x4000; // size
		parameters[2].value = PROT_READ | PROT_WRITE | PROT_EXEC; // prot
		parameters[3].value = 0x20 | MAP_PRIVATE; // flags
		parameters[4].value = 0; //fd
		parameters[5].value = 0; //offset

		unsigned long map_addr;
		ret = find_func_by_got(pid, "mmap", NULL, &map_addr); // TODO use find by module base
		if (ret != 0) {
			ALOGE("find mmap failed\n");
			return NULL;
		}

		unsigned long mem_addr;
		// it won't cause recursively call because every param is of type CONSTANT.
		ret = ptrace_call(pid, map_addr, parameters, 6, &mem_addr);
		if (ret != 0 || mem_addr == -1) {
			ALOGE("call mmap failed!\n");
			return NULL;
		} else {
			ALOGI("remote mmap succeed. 0x%lx\n", mem_addr);
		}

		sMapBase = mem_addr;
		addr = mem_addr;

	} else {
		addr = sMapBase + sOffset;
	}
	sOffset += len;

	return addr;
}

#if defined(LINUX)
bool ptrace_is_remote_interrupted_in_syscall(pid_t pid) {

	// TODO NOT implemented!! not found a good way yet.
	// in actual test, remote porcess will probably be interrupted when it's in kernel status.

	return true;
}
#endif
