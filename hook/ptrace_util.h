#ifndef PTRACE_H_
#define PTRACE_H_

#include <sys/types.h>
#include <stdint.h>
#if defined (LINUX)
#include <sys/user.h>
#elif defined (ANDROID)
#include <asm/ptrace.h>
#endif
#include <stdbool.h>

#if defined(ANDROID)
// #error "set REGs struct and names on Android"

#define REG_AX_INDEX 0

#define REG_SP ARM_sp
#define REG_IP ARM_pc

#define REG_PASS_PARAM_0 ARM_r0
#define REG_PASS_PARAM_1 ARM_r1
#define REG_PASS_PARAM_2 ARM_r2
#define REG_PASS_PARAM_3 ARM_r3
#define REG_PASS_PARAM_NUM 4
#define REG_PASS_PARAM(x) REG_PASS_PARAM_##x

#elif defined(LINUX)
#define pt_regs         user_regs_struct
// see sys/user.h & sys/reg.h
#if __WORDSIZE == 64

#define REG_SP rsp
#define REG_SP_INDEX RSP
#define REG_IP rip
#define REG_IP_INDEX RIP
#define REG_AX rax
#define REG_AX_INDEX RAX
#define REG_ORIG_AX orig_rax
#define REG_ORIG_AX_INDEX ORIG_RAX

#define REG_SI rsi
#define REG_SI_INDEX RSI
#define REG_DI rdi
#define REG_DI_INDEX RDI
#define REG_CX rcx
#define REG_CX_INDEX RCX
#define REG_DX rdx
#define REG_DX_INDEX RDX
#define REG_R8 r8
#define REG_R8_INDEX R8
#define REG_R9 r9
#define REG_R9_INDEX R9

#define REG_PASS_PARAM_0 REG_DI
#define REG_PASS_PARAM_1 REG_SI
#define REG_PASS_PARAM_2 REG_DX
#define REG_PASS_PARAM_3 REG_CX
#define REG_PASS_PARAM_4 REG_R8
#define REG_PASS_PARAM_5 REG_R9
#define REG_PASS_PARAM_NUM 6
#define REG_PASS_PARAM(x) REG_PASS_PARAM_##x

#else

#define REG_SP esp
#define REG_SP_INDEX UESP
#define REG_IP eip
#define REG_IP_INDEX EIP
#define REG_AX eax
#define REG_AX_INDEX EAX
#define REG_ORIG_AX_INDEX ORIG_EAX
#endif

#endif

#define CALL_PARAM_TYPE_CONSTANT 0
#define CALL_PARAM_TYPE_POINTER 1

#if (defined(LINUX) && __WORDSIZE == 32)
#define PARAM_ONLY_BY_STACK
#endif

typedef struct {
	int type;
	int size;										// if type is POINTER, the bytes count of the buf pointed by the value, don't forget the ending \n of string. unused for type CONSTANT.
	long value;
#ifndef PARAM_ONLY_BY_STACK
	int index;										// the index of this param in function declaration, left to right, base 0.
#endif
}call_param_t;

// TODO multi ptrace_attach call will fail, but other functions may be called in different threads, do we need thread-safe ?

// ATTENTION: these functions have NOT been tested under multi-thread condition.

// after attached, child stopped until continue or detach called.
int ptrace_attach(pid_t pid);
int ptrace_detach(pid_t pid);
int ptrace_continue(pid_t pid);
int ptrace_syscall(pid_t pid);

// after stopped. use these functions to control child
int ptrace_get_reg(pid_t pid, int index,  long* out);
int ptrace_set_reg(pid_t pid, int index, long value); // i found that pokeuser not working. don't use this.
int ptrace_get_regs(pid_t pid, struct pt_regs * regs);
int ptrace_set_regs(pid_t pid, const struct pt_regs * regs);

int ptrace_read_bytes(pid_t pid, const unsigned long *src, void *buf, size_t size);
int ptrace_write_bytes(pid_t pid, unsigned long *dst, const void *buf, size_t size);
int ptrace_push_bytes(pid_t pid, const void *buf, size_t size, unsigned long* sp);
int ptrace_push(pid_t pid, long value, unsigned long* sp);
int ptrace_strlen(pid_t pid, const unsigned long *addr);
int ptrace_read_str(pid_t pid, const unsigned long *addr, void* buf, size_t size);
// caller to free the returned pointer
char* ptrace_get_str(pid_t pid, const unsigned long *addr);

// this function will change the registers. you may want to save the registers before and restore them after calling this.
int ptrace_call(pid_t pid, unsigned long addr, const call_param_t *params, int num_params, long* retVal);
int ptrace_wait_signal(pid_t pid, int sig);

#if defined(LINUX)
bool ptrace_is_remote_interrupted_in_syscall(pid_t pid);
#endif

#endif /* PTRACE_H_ */
