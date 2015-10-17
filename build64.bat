@echo off

cl /c /Tpphantasm64.c

link /out:phantasm64.exe phantasm64.obj
