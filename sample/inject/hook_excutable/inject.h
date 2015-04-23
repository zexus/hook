int MZHOOK_InjectLibToProcess(int nTargetPid, char * pcSrcLib, char * pcDstLib, char * pcSrcFunc, char * pcDstFunc, char * pcFuncLib);
int MZHOOK_InjectProcess(int nTargetPid, char * pcSrcLib, char * pcSrcFunc, char * pcDstFunc);
int MZHOOK_FindPidOfProcess(const char * pcProcessName);