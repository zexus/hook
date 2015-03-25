#include <stdio.h>

int Hook_Entry()
{
    printf("Hook_Entry++++++++++++++++++++++++++++++++\n");
    return 0;
}

int foo() {
    printf("foo called++++++++++++++++++++++++++++++++++\n");
    return 0;
}