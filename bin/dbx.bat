@echo off
if "%1"=="h" (
    type %~dp0Lib\windbg\windbg.dbg | clip.exe
) else if 0==0 (
	%SCOOP%\apps\notepadplusplus\current\notepad++.exe %~dp0Lib\windbg\windbg.dbg
)
@echo on