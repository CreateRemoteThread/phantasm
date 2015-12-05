@echo off

del *.obj

IF [%1]==[64] cl /c /I beainclude /Tpphantasm64.c
IF [%1]==[64] cl /c /Tporacle.c
IF [%1]==[64] link /out:phantasm64.exe phantasm64.obj oracle.obj beasrc/BeaEngine.obj

IF [%1]==[32] cl /c /I beainclude /Tpphantasm64.c
IF [%1]==[32] cl /c /Tporacle.c
IF [%1]==[32] link /out:phantasm.exe phantasm64.obj oracle.obj beasrc/BeaEngine.obj

IF [%1]==[bea] cd beasrc
IF [%1]==[bea] cl /c /I ../beainclude /Tp BeaEngine.c
IF [%1]==[bea] cd ..

IF [%1] EQU [] ECHO build {target}. Valid targets are "64", "bea"