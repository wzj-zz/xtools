@echo off
if "%1"=="new" (
	s ki KeyPatch64.exe
	ahk %~dp0..\bin\KeyPatch\KeyPatch64.ahk
) else if "%1"=="n" (
	%SCOOP%\apps\notepadplusplus\current\notepad++.exe %~dp0..\bin\KeyPatch\KeyPatch64.ahk
) else if "%1"=="ki" (
	s ki KeyPatch64.exe
) else if "%1"=="l" (
	regedit /s %~dp0..\bin\KeyPatch\Enable_Win_L.reg
) else if "%1"=="xl" (
	regedit /s %~dp0..\bin\KeyPatch\Disable_Win_L.reg
) else if "%1"=="patch" (
	regedit /s %~dp0..\bin\KeyPatch\KeyPatch.reg
) else if "%1"=="h" (
	if "%2"=="" (
		type %~dp0.\Lib\key_man.txt
	) else (
		type %~dp0.\Lib\key_man.txt | findstr /i %2
	)
) else if 0==0 (
    psexec.exe -d -i -s %~dp0..\bin\KeyPatch\KeyPatch64.exe
    REM s open %~dp0..\bin\KeyPatch\KeyPatch64.exe
)
@echo on