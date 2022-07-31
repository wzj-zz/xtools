@echo off
if "%1"=="" (
	ipconfig
) else (
	ipconfig | findstr /i %1
)
@echo on