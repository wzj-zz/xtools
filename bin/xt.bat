@echo off
if "%1"=="" goto exec_code_from_clip
goto exec_xtools_exec


:exec_code_from_clip
p %~dp0Lib\xtools_exec.py -c
goto end

:exec_xtools_exec
p %~dp0Lib\xtools_exec.py %*
goto end

:end
@echo on