.586p
.model flat,stdcall
option casemap:none

include /masm32/include/windows.inc
include /masm32/include/kernel32.inc
include /masm32/include/user32.inc

includelib /masm32/lib/kernel32.lib
includelib /masm32/lib/user32.lib

.data
abc db "asdf",0


.code

_start:

invoke MessageBoxA,0,ADDR abc,ADDR abc,MB_OK
invoke ExitProcess,0

end _start