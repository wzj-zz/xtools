@echo off
if "%1"=="elf" (
	open %~dp0..\help\ELF.pdf
) else if "%1"=="pe" (
	open %~dp0..\help\PE.jpg
) else if "%1"=="peo" (
	open %~dp0..\help\PE_OFF.pdf
) else if "%1"=="pef" (
	open %~dp0..\help\PE_FULL.pdf
) else if "%1"=="i1" (
	open %~dp0..\help\INTEL1.pdf
) else if "%1"=="i2" (
	open %~dp0..\help\INTEL2.pdf
) else if "%1"=="i3" (
	open %~dp0..\help\INTEL3.pdf
) else if "%1"=="i4" (
	open %~dp0..\help\INTEL4.pdf
) else if "%1"=="" (
	open %~dp0..\help\Win32.chm
)
@echo on