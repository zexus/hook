#include <stdio.h>
#include <unistd.h>

int Hook_Entry_Test(char * pcString, int nValue1, int nValue2, int nValue3, int nValue4, int nValue5, int nValue6)
{
    printf("Hook_Entry_Test++++++++++++++++++++++++++%d\n", getpid()); // _getpid()
    printf("pcString+++++++++++++++++++++++++++++++++%s\n", pcString);
    return 0;
}