@echo off
if "%1"=="" (
	cd /d C:\Users\%username%\source\repos
	cls
) else (
	cd /d %1
)
@echo on