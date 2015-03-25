#include <stdio.h>
#include <unistd.h>

int Hook_Entry()
{
    printf("Hook_Entry++++++++++++++++++++++++++++++++%d\n", getpid()); // _getpid()
    return 0;
}

int foo() {
    printf("foo called++++++++++++++++++++++++++++++++++%d\n", getpid());   // _getpid()
    return 0;
}