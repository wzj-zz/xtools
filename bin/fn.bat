@echo off
if "%1"=="" (
	netstat -ano
) else (
	netstat -ano | findstr /i %1
)
@echo on