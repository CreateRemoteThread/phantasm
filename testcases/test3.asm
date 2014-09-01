.586p
.model flat,stdcall
option casemap:none

;; BEGIN--
;; DO c:\masm32\bin\bldall.bat %namePrefix
;; END--

include /masm32/include/windows.inc
include /masm32/include/kernel32.inc
include /masm32/include/user32.inc

includelib /masm32/lib/kernel32.lib
includelib /masm32/lib/user32.lib

.data

a_ db "a",0


.code

_start: 

invoke MessageBox,0,ADDR a_,ADDR a_,MB_OK

mov eax,4
int 3
invoke ExitProcess,0
ret

end _start