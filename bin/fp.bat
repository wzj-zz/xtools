@echo off
if "%1"=="" (
	tasklist
) else (
	tasklist | findstr /i %1
)
@echo on