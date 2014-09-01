@echo off

if "%1" == "phantasm" link /debug /out:phantasm.exe phantasm.obj geist.obj resolute.obj libdis/*.obj