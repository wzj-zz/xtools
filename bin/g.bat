@echo off
if "%1"=="clash" (
	open "%~dp0..\utils\Clash\Clash for Windows.exe"
) else if "%1"=="every" (
	copy %~dp0..\config\Everything\Everything.ini %SCOOP%\apps\everything\current\Everything.ini
	copy %~dp0..\config\Everything\IbEverythingExt\bin\IbEverythingExt.yaml %SCOOP%\apps\everything\current\IbEverythingExt.yaml
	copy %~dp0..\config\Everything\IbEverythingExt\bin\WindowsCodecs.dll %SCOOP%\apps\everything\current\WindowsCodecs.dll
	open %SCOOP%\apps\everything\current\Everything.exe
) else if "%1"=="snap" (
	copy %~dp0..\config\Snipaste\config.ini %SCOOP%\apps\snipaste-beta\current\config.ini
	open %SCOOP%\apps\snipaste-beta\current\Snipaste.exe
) else if "%1"=="lt" (
	copy %~dp0..\config\Listary\Preferences.json %SCOOP%\apps\listary\current\UserData
	open %SCOOP%\apps\listary\current\Listary.exe
) else if "%1"=="x" (
	ki vcxsrv.exe
	start "" "%SCOOP%\apps\vcxsrv\current\vcxsrv.exe" :0 -multiwindow -clipboard -wgl
) else if "%1"=="xr" (
	ki vcxsrv.exe
	start "" "%SCOOP%\apps\vcxsrv\current\vcxsrv.exe" :0 -multiwindow -clipboard -wgl -ac
) else if "%1"=="xe" (
	ki vcxsrv.exe
	start "" "%SCOOP%\apps\vcxsrv\current\vcxsrv.exe" :0 -multiwindow -clipboard -wgl -ac
	wsl.exe --set-default ubuntu_2
	wsl.exe pkill emacs
	wsl.exe emacs --daemon
)
@echo on