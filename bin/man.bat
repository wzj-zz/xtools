@echo off
if "%1"=="" (
	type %~dp0.\Lib\man.txt
) else (
	type %~dp0.\Lib\man.txt | findstr /i %1
)
@echo on