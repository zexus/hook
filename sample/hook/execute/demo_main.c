#include <stdio.h>
#include<sys/mman.h>

int main()
{
    while (1) {
        Hook_Entry_Test("Welcome", 9, 9, 9, 9, 9, 9);
        sleep(1);
    }

    return 0;
}