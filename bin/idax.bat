@echo off
if "%1"=="h" (
    type %~dp0.\Lib\ida\idabase.py | clip.exe
) else if 0==0 (
	%SCOOP%\apps\notepadplusplus\current\notepad++.exe %~dp0Lib\ida\idabase.py
)
@echo on