#include <stdio.h>
#include<sys/mman.h>

int main()
{
    int nTarget1 = 1;
    int nTarget2 = 2;

    while (1) {
        Hook_Entry_Test("Welcome", 9, 9, 9, 9, 9, 9);
        printf("nTarget1+++++++++++++++++++++++++++++++++%d\n", nTarget1);
        printf("nTarget1+++++++++++++++++++++++++++++++++%p\n", &nTarget1);
        printf("nTarget2+++++++++++++++++++++++++++++++++%d\n", nTarget2);
        printf("nTarget2+++++++++++++++++++++++++++++++++%p\n", &nTarget2);
        sleep(1);

        // void * pcMapAddr = mmap(0, 0x4000, PROT_READ | PROT_WRITE | PROT_EXEC, 0x20 | MAP_PRIVATE, 0, 0);
        // if ((void *)-1) == pcMapAddr) {
        //      printf("mmap memory error.\n");
        //  } else {
        //      printf("pcMapAddr:+++++++++++++++%p\n", pcMapAddr);
        //      munmap(pcMapAddr, 0x4000);
        //  }
        // foo();
    }

    return 0;
}