@echo off

cl /c /I beainclude /Tpphantasm64.c

link /out:phantasm64.exe phantasm64.obj beasrc/BeaEngine.obj
