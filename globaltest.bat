@echo off

echo -----------------------------------------------
echo *          THIS TAKES ABOUT 30 MINUTES        *
echo *   GO FOR A WALK, SEE YOU WHEN YOU GET BACK  *
echo -----------------------------------------------

rm samples/*

phantasm c:\projects\phantasm\testcases\ldr_clean.exe > samples/ldr_clean.run
phantasm c:\projects\phantasm\testcases\ldr_upx.exe > samples/ldr_upx.run
python gdiff.py -f samples/ldr_clean.run -f samples/ldr_upx.run