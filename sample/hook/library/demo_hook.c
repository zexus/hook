#include <stdio.h>
#include <unistd.h>

int Hook_Entry_Test(char * pcString, int nValue1, int nValue2, int nValue3, int nValue4, int nValue5, int nValue6)
{
    printf("Hook_Entry+++++++++++++++++++++++++++++++%d\n", getpid()); // _getpid()
    printf("pcString+++++++++++++++++++++++++++++++++%s\n", pcString);
    printf("nValue1++++++++++++++++++++++++++++++++++%d\n", nValue1);
    printf("nValue2++++++++++++++++++++++++++++++++++%d\n", nValue2);
    printf("nValue3++++++++++++++++++++++++++++++++++%d\n", nValue3);
    printf("nValue4++++++++++++++++++++++++++++++++++%d\n", nValue4);
    printf("nValue5++++++++++++++++++++++++++++++++++%d\n", nValue5);
    printf("nValue6++++++++++++++++++++++++++++++++++%d\n", nValue6);
    return 0;
}

int foo() {
    printf("foo called++++++++++++++++++++++++++++++++++%d\n", getpid());   // _getpid()
    return 0;
}