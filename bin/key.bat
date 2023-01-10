@echo off
set key_man_txt=dtxt(b'H4sIAL42vWMC/61XW28TRxR+Nr/iWDwkyCYmAXEJElJIUkGxSZoUqJQaNNkdxxPvziw7s74EReKlpaSgtA9IfWsfentpS8VDQdD+mhjap/6FzpwZb+z1JkRKIyXOzPed75w5c+bM+AbtLRPlNc+fg2s0iGZh7eRsh/EyFGfnAlWGu7PzKg7KUJpdbbKGqp84fZwfgBOFwk0RhySAmvDpsdXWbi6t1OaqdYBF6QHA6SvwQP+3PQqUCALXREizyGVrwv0ssInAgujwLNJC5FaUnW/ifJU2VBYJEFlhG80xKDHQ3VwrZqFcsx4qXl3NzgtrMw5wBEq5jkKH5XoqG7CUm7spC+Ukb90iec6ohXJ9VSyWl/TIQuNZ9zETyxsLYyYNh4zbTFixxvSZbYhElEQQUp5kSGtVfQCgejVRSvC6Njhp1wOrinktUE0K+qD4ogNK4CjQKEzquQsgYiDrok1PZTVXzGmClWFRm4kDVWMDv092NSIehU+s7IzV1cuGkHRZyLZSzcNlNrAOig8+JuvbUGVSAQkCIFEUMI8oJrh8j8B9I1B88MG5bfgoYQrjj2KxEZMQJhNJQc8JjtM+lS0lIh2YdiGbiQIdH88KXsKI0sR3mO5Ug8REMW0zkchUysQ2fUY7CHpZnTNOZ5DrESFOu+ooIp4V8WE+pkRRIEcxip1nk5MFGlBtZ3x6SRxTfiS3baNwsiRBejGlXDaFOoyukI57mEGwgduuRoNhsGbrxjYpU6DD4B3GbS/cTMLIpMyWkoT1HnAS0gwVj/CHhrpOVUfHC1JXYEDi1G5SaisgzdY92h2pIGOOGz4voh4QT7H2oHAzLNzOZSJdMl1xC+429IjJNUqfGqUFJqOA9OSIsRPV5etRKYHxhrm2zCkAwn0bYz53QmJiTK7mAxZdFST2M25xK6zzw4Ui5h+mg7eHO/bTMLlOvFZ2hWyIMgOTehUdrZNl4d01Z1JuKtscN5iLIpjTK63pg67/6OObsWmN2ODRer+RXXk4YnrHVYZuANQ3dXUjfZRM6RrBdpMoYf7PVVsrwxRMAJZu3SivUE/EfiarGdMxozSc4R7cJEoXvu6EMUra8A7wnHGAzXA5kU23vgzcQVhXZy5q5VOO6cMuS0NE49U+YBY5WQ9sogar8EI/kzB9nZXMK0nzlzg1NeW1Mm4dvCASI5dlVG1UjrTIFY2HUImgxJtoAMNtFtqH3j4Pk1Wq4kWY8rBULPN/eGEWUrfHfl/evl6rX+dNGuurq0V7ctZOFchl2Gw1A0gY9ATwEMpTuuNVIvAblqEvlZgMm+jX6f3C6SuFxa6W2s8LqikDuLaMExNm4u7wjIcznhu1cdR2oy0cbblRF0ddN5IojVkeSG0ggbhRbEa+vZoCxgchdZDUs6OYRlQxbMgiojG2Qf1VgSdhfU0vse5scLWZvLikgJqA9paMO7CGJTIwcSNgEuj9RJduYE6sbnnBsffOFMJQXR27FGpLt1YX6wUGLdiEoMAhhASEdqKreO/ljv79Evp//Aj93RfmE4e7L9ysIeBoBybf/fS6v/Nz/7PHb7979O+bJ2+fPN77c5cEqv/46bs3D/u7v+29/qH/1df933f7r579/derd8+evN35pv90xxqWwVrggRuxebT7z8NvLenUIF64XLAh9p9/bl069188tw72Xv7S//7XlO5DwxnU7i0s3bmpP24tp4vX/c6h3WnozqTzBCR0HeKezINX7uB5kXIvVKYd8zr3pio+9aZ02/J0BdrCSokXKzNjRMZ1GepvjzKiuhmn1EuVs2NUfPwmoaWmzOKFSnHcf6dJaZAfRfFipThzgMFINPsWlyrFswdY5Ad1rnJ+jB8LNXhubATHLt//ALTBSQToDwAA')

if "%1"=="" goto run_key
if "%1"=="new" goto compile_key
if "%1"=="n" goto edit_key
if "%1"=="ki" goto kill_key
if "%1"=="l" goto enable_win_L
if "%1"=="xl" goto disable_win_L
if "%1"=="patch" goto patch_key
if "%1"=="revert" goto revert_key
if "%1"=="h" if "%2"=="" goto show_man

:show_man_search
echo %key_man_txt% | p %~dp0Lib\xtools_exec.py -x -e stdout | findstr /i %2
goto end

:show_man
echo %key_man_txt% | p %~dp0Lib\xtools_exec.py -x -e stdout
goto end

:run_key
psexec.exe -d -i -s %~dp0..\bin\KeyPatch\KeyPatch64.exe
goto end

:compile_key
s ki KeyPatch64.exe
ahk %~dp0..\bin\KeyPatch\KeyPatch64.ahk
goto end

:edit_key
%SCOOP%\apps\notepadplusplus\current\notepad++.exe %~dp0..\bin\KeyPatch\KeyPatch64.ahk
goto end

:kill_key
s ki KeyPatch64.exe
goto end

:enable_win_L
regedit /s %~dp0..\bin\KeyPatch\Enable_Win_L.reg
goto end

:disable_win_L
regedit /s %~dp0..\bin\KeyPatch\Disable_Win_L.reg
goto end

:patch_key
regedit /s %~dp0..\bin\KeyPatch\KeyPatch.reg
goto end

:revert_key
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Keyboard Layout" /f
goto end

:end
set key_man_txt=
@echo on