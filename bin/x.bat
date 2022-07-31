@echo off
set xxx=%cd%
if "%1"=="*" (
	C:\"Program Files (x86)\Microsoft Visual Studio"\2019\Community\VC\Auxiliary\Build\vcvars64.bat
) else (
	C:\"Program Files (x86)\Microsoft Visual Studio"\2019\Community\VC\Auxiliary\Build\vcvars32.bat
)
cd /d %xxx%
set xxx=
@echo on
