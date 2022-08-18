@echo off
if "%1"=="" goto run_auto
if "%1"=="new" goto compile_auto
if "%1"=="n" goto edit_auto
if "%1"=="ki" goto kill_auto
if "%1"=="h" goto show_man

:show_man
type %~dp0.\Lib\auto.ahk | win32yank.exe -i
goto end

:run_auto
cd /d C:/Users/%username%/Desktop
s open %~dp0Lib\auto.exe
goto end

:compile_auto
s ki auto.exe
ahk %~dp0Lib\auto.ahk
goto end

:edit_auto
%SCOOP%\apps\notepadplusplus\current\notepad++.exe %~dp0Lib\auto.ahk
goto end

:kill_auto
s ki auto.exe
goto end

:end
@echo on