#include <stdio.h>
#include <errno.h>
#include <sys/ptrace.h>

typedef union {
	long value;
	char chars[sizeof(long)];
}WORDUN;

int ptrace_write_bytes(pid_t pid, unsigned long *dst, const void *buf, size_t size)
{
	int wordCount, byteRemain;
	unsigned long *dstAddr;
	const long *dataAddr;
	WORDUN un;
	int i;

	if (dst == NULL || buf == NULL || size < 0) {
		printf("[+] ptrace_write_bytes invalid params\n");
		return EINVAL;
	}

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

int main()
{
	int nRet = -1;
	int nValue = 6;

	nRet = ptrace(PTRACE_ATTACH, 4982, NULL, NULL);
	nRet = ptrace_write_bytes(4982, 0xbed1c82c, &nValue, sizeof(int));
	nRet = ptrace(PTRACE_DETACH, 4982, NULL, NULL);
	if(0 != nRet)
	{
		printf("write data error\n");
		return -1;
	}
	
	return nRet;
}