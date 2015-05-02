@echo off

if "%1" == "verbose" cl /DSUPERVERBOSE /c /O2 /Tp phantasm.c

if "%1" NEQ "verbose" cl /c /O2 /Tp%1