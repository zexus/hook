#include <stdio.h>
#include <unistd.h>

int Hook_Entry(int nValue, int nTargetPid)
{
    printf("Hook_Entry++++++++++++++++++++++++++++++++%d\n", getpid()); // _getpid()
    printf("nValue++++++++++++++++++++++++++++++%d\n", nValue);
    printf("nTargetPid++++++++++++++++++++++++++++++++++%d\n", nTargetPid);
    return 0;
}

int foo() {
    printf("foo called++++++++++++++++++++++++++++++++++%d\n", getpid());   // _getpid()
    return 0;
}