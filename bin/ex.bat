@echo off
if "%1"=="" (
	explorer .
) else (
	explorer %1
)
cls
@echo on