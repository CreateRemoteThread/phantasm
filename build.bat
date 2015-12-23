@echo off

del *.obj

IF [%1]==[64] cl /D ARCHI_64 /O2 /Zi /c /I beainclude /Tpphantasm64.c
IF [%1]==[64] cl /D ARCHI_64 /O2 /Zi /c /Tporacle.c
IF [%1]==[64] cl /D ARCHI_64 /O2 /Zi /c /Tptinker.c
IF [%1]==[64] link /OPT:REF /OPT:ICF /INCREMENTAL:NO /DEBUG /out:phantasm64.exe phantasm64.obj oracle.obj tinker.obj beasrc/BeaEngine.obj

IF [%1]==[32] cl /O2 /Zi /c /I beainclude /Tpphantasm64.c
IF [%1]==[32] cl /O2 /Zi /c /Tporacle.c
IF [%1]==[32] link /OPT:REF /OPT:ICF /INCREMENTAL:NO /DEBUG /out:phantasm.exe phantasm64.obj oracle.obj beasrc/BeaEngine.obj

IF [%1]==[bea] cd beasrc
IF [%1]==[bea] cl /O2 /Zi /c /I ../beainclude /Tp BeaEngine.c
IF [%1]==[bea] cd ..

IF [%1] EQU [] ECHO build {target}. Valid targets are "64", "bea"