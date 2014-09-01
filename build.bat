@echo off

cl /c /Tpphantasm.c
cl /c /Tpgeist.c
cl /c /Tpresolute.c

link /out:phantasm.exe phantasm.obj geist.obj resolute.obj libdis/*.obj
