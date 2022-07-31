@echo off
if "%1"=="" (
	open %~dp0..\utils\ahk\ahk.exe
) else (
	%~dp0..\utils\ahk\ahk.exe /in %1
)
@echo on