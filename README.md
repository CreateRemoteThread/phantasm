phantasm
========

phantasm is a minimalist execution tracer for windows. the simplest use case
is to run it as follows:

phantasm.exe test.exe -arg1 -arg2

this will log all instructions within the test.exe module, as well as log all
function calls it knows about (as per arghooks.lst)

phantasm operates by messing with memory protection, so it may interfere with
applications which make use of page permissions. ymmv, 32-bit executables only
for now.

gdiff
=====

gdiff is the accompanying execution visualisation tool, and is heavily work in
progress.