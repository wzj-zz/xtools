@echo off
if "%1"=="" (
	open %~dp0ahk\ahk.exe
) else (
	%~dp0ahk\ahk.exe /in %1
)
@echo on