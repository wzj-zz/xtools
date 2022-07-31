@echo off
if "%1"=="new" (
	s ki auto.exe
	ahk %~dp0Lib\auto.ahk
) else if "%1"=="n" (
	%SCOOP%\apps\notepadplusplus\current\notepad++.exe %~dp0Lib\auto.ahk
) else if "%1"=="ki" (
    s ki auto.exe
) else if "%1"=="h" (
    type %~dp0.\Lib\auto.ahk | clip.exe
) else if 0==0 (
    cd /d C:/Users/%username%/Desktop
    s open %~dp0Lib\auto.exe
)
@echo on