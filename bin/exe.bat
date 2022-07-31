@echo off
if "%1"=="h" (
    type %~dp0.\Lib\xtools_exec.py | clip.exe
) else if 0==0 (
	%SCOOP%\apps\notepadplusplus\current\notepad++.exe %~dp0Lib\xtools_exec.py
)
@echo on