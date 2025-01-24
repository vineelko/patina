@echo off

:: "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
:: editbin.exe /rebase:base=0x180000000 "C:\r\qemu_rust_bins\target\x86_64-unknown-uefi\debug\deps\qemu_q35_dxe_core-9eb1e2f68d36020c.efi"

del *.obj
del *.exe
del *.dll
del *.exp
del *.lib
del *.pdb

ml64 /c /Fo getrsp.obj getrsp.asm
cl /LD /MT x64.c getrsp.obj /Zi /link /DEBUG /INCREMENTAL:NO
cl test.c /Zi /link /DEBUG /INCREMENTAL:NO
:: link -dump -unwindinfo x64.dll > unwindinfo.txt

del *.obj
del *.exp
del *.lib
