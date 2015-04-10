#include <stdio.h>
#include <unistd.h>
#include "demo_hook.h"

int (*Old_Hook_Entry_Test)(char * pcString, int nValue1, int nValue2, int nValue3, int nValue4, int nValue5, int nValue6) = -1;

int hook_entry()
{
    return 0;
}

int hook_entry_test(char * pcString, unsigned long nValue1, int nValue2, int nValue3, int nValue4, int nValue5, int nValue6) {
    Old_Hook_Entry_Test = Hook_Entry_Test;
    printf("Old_Hook_Entry_Test Address++++++++++++++%p\n", Hook_Entry_Test);
    printf("nValue1++++++++++++++++++++++++++++++++++%p\n", nValue1);
    hook_entry();
    return 0;
}
