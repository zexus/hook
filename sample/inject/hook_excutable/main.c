#include <stdio.h>
#include "inject.h"

int main()
{
    int nTargetPid = -1;
    int nRet = -1;
    //char * pcFuncLib = "/system//libEGL.so";
    char * pcFuncLib = NULL;
    
    if (NULL != pcFuncLib)
    {
        printf("MZHOOK_InjectLibToProcess+++++\n");
        char * pcSrcLib = "/system/lib/libhook_egl.so";
        char * pcDstLib = "/system/lib/libsurfaceflinger.so";
        char * pcSrcFunc = "s_fnOnNewFunctionAddress";
        char * pcDstFunc = "eglSwapBuffers";
    
        nTargetPid = MZHOOK_FindPidOfProcess("/system/bin/surfaceflinger");
        MZHOOK_InjectLibToProcess(nTargetPid, pcSrcLib, pcDstLib, pcSrcFunc, pcDstFunc, pcFuncLib);
    }
    else
    {
        printf("MZHOOK_InjectProcess+++++\n");
        nTargetPid = MZHOOK_FindPidOfProcess("/system/bin/demo_main");
        char * pcSrcLib = "/system/lib/libhook_test.so";
        char * pcSrcFunc = "New_Hook_Entry_Test";
        char * pcDstFunc = "Hook_Entry_Test";
        MZHOOK_InjectProcess(nTargetPid, pcSrcLib, pcSrcFunc, pcDstFunc);
    }

    return 0;
}