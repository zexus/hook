#include <stdio.h>
#include <unistd.h>

volatile int Hook_Entry_Test(char * pcString, int nValue1, int nValue2, int nValue3, int nValue4, int nValue5, int nValue6)
{
    printf("Hook_Entry_Test++++++++++++++++++++++++++%d\n", getpid()); // _getpid()
    return 0;
}

volatile int Hook_internal()
{
    Hook_Entry_Test("Hook_internal", 1, 2, 3, 4, 5, 6);
    return 0;
}