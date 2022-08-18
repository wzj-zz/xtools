@echo off
set key_man_txt=dtxt(b'H4sIAD8O/mIC/61XS28URxA+LxL/oVYcbLSLFxuLh5GQjG2Ew67t2AEiOQvqnen1tHeme5ju2YeRJS4JwQE5OSDllhzyuiQh4hAQJL/GC8kpfyH9mn3MjMGSsWSvu7/6vqqurq7uvYF7a0g43vlZuI79cA42T811CC1DcW7eF2W4M7cgIr8MpbkNjzRF/eSJM8f5ATh5olBYYVGAfKgxF38Avc2V1fXafLUOsMQdADhzBe7L/3ZTSAlp5DoLcAa6bEjUzSDbGllkHZqBWhq6GWYATwNV3BQZyNfQOtnyslissDv5PGKwfGJPi17dyADMsHIQqpFSvrPAgvneygot5edxymB5iWwYKNchNli+v4oBc7cgNFjOHrg6J2tbi1lS00I5rAmj15w+uwshC+MQAkzjtNVmVR4NqF6NhWC0LhmnzLJgQxCnBcLDII+QyzogmB75EoVJOXcBWASowdr4dEZ0XR00WB9VNQk5VDZS8Ht1N0LkYPjU6M4YYbl0CFCXBGRnIPoenS1dFMX7n6DGLlQJF4B8H1AY+sRBgjDK36dwTykU71+b3YWPYyL0EsKIbUUogMmYY5BzjOppF/OWYKEMTfrgXixARkgzipd0TIPsd4hsZElywgi3CYv5QEtFN31WevB7GaGzVihJ+JgSxV1xJBXHqLiwEGEkMKAjsSLrW+VlEftYEpVXJ44iTI/muK0kTpU4cCfCmHKPiXfaC22vtzIN6S5veh72x9CaqSDTwFStjqG3CTW9cjsOQpU5U1UcGj2gKMBpW32qP1K2DSw6Mmjgshp9FA2Ik1zSAHmtu7g7XkyKr7d+gYU9QI4g7aSK02Z6Y9cQt0m1pc6o3dqjJllJfaakFgkPfdTjY2yrKmvZwZwDoU11v6kzAYi6Jsp82wmuk6PyteCT8CpDkZv2q3fEeH+3Ukjcdwrp+8X2gWmYbCCnlVkkGbGZgUm5kI5UypjpG25eJV7VuTp+MB+GMC9XW5NHX/6R5zlNao2R9FE7AsssPxjj3rYlInsCdlWF3Ri8YqZksegWFAum/s+X2yzDFEyALuO6kl7HDovcVG7T3AxrENBob/aQkIdA9sdIa5oAD3Gd9qBb5FrMPbvENN7RuCzUfNh4GBipBm1TNWqpPJsXzxJFDd+kK1mJE7jptMnLrqReVpKwSrGqL6eV9mzxRRYrwYxJ1URmrZaowNEozDXK9UWV4HCLBPaFODTUWStVpcehna4aa/lBXqeFoefjv01vLdfqy9TDkbzcWrjH5+xcAV2G7ZbnQ0ygx4AGUJ6SrbASgtu0JvLaidAYST5u7xXOXCksdaXaSH60oFBI0rX1zISauTM25egpJxm29bCdDHf0cCcZdvWwmwy5dqCTPtDb0iYoGUZq6JpLzCd0EFtHm/XsMMIhFkR3bRbiSHdK+cWDxkF9Uy63nrD00lNZsikCMQHtHR51YFOXzYBjh0A44HuxrGlfnWfZFv0PsJu6Okbr7fj1UVu9ubFULxBowTb4BQoBxMCkG1nfBy/25O9X0P/zJ+jvP1eferj/3M4qAz3ag8m3P7/q7/3S//zRm+8f/vf68ZvHjw7+2ke+6D968vb1g/7+7wevfux//U3/j/3+y6f//P3y7dPHb/a+7T/ZM8QyGIY+imOch/v/PvjOGJ0eBAyXCybG/rMvjE/r/8tnxsPBi1/7P/w2tHehaRm1u4urt1fkx8214fplU7Rwdxq6M0MAAYeuheyLO3kjJy+SofGFyrQ1XabOVMXFzpTsbI6sR1NkQ8uLlZmMJaGyJuXXUh5i2bSHtpcq5zK2+vEcB8Z2aFq8UClmQ+h4GPuHBFK8WCnOHMIYC2iEcqlSPHcI5ZC4ZivnM4SIieSNsuUfv5b/Bzg9iCZJEAAA')

if "%1"=="" goto run_key
if "%1"=="new" goto compile_key
if "%1"=="n" goto edit_key
if "%1"=="ki" goto kill_key
if "%1"=="l" goto enable_win_L
if "%1"=="xl" goto disable_win_L
if "%1"=="patch" goto patch_key
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

:end
set key_man_txt=
@echo on