@echo off
if "%1"=="" goto win32
if "%1"=="i1" goto intel_1
if "%1"=="i2" goto intel_2
if "%1"=="i3" goto intel_3
if "%1"=="i4" goto intel_4
if "%1"=="elf" goto elf
if "%1"=="pef" goto pe_full
if "%1"=="peo" goto pe_off
if "%1"=="pe" goto pe

:win32
open %~dp0..\help\Win32.chm
goto end

:intel_1
open %~dp0..\help\INTEL1.pdf
goto end

:intel_2
open %~dp0..\help\INTEL2.pdf
goto end

:intel_3
open %~dp0..\help\INTEL3.pdf
goto end

:intel_4
open %~dp0..\help\INTEL4.pdf
goto end

:elf
open %~dp0..\help\ELF.pdf
goto end

:pe_full
open %~dp0..\help\PE_FULL.pdf
goto end

:pe_off
open %~dp0..\help\PE_OFF.pdf
goto end

:pe
open %~dp0..\help\PE.jpg
goto end

:end
@echo on