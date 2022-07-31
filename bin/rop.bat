@echo off
if "%1"=="" (
	p %~dp0Lib\rop.py --console
) else if "%1"=="-h" (
	p %~dp0Lib\rop.py --help
) else (
	p %~dp0Lib\rop.py --binary %*
)
@echo on