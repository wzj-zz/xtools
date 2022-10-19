@echo off
set key_man_txt=dtxt(b'H4sIAHzvT2MC/61XS28URxA+L1L+Q6042GgXLzaIh5GQjO0Iwi527ACRnAX1zvR6xzvTPUz37MPIEpeE4ICcHJBySw55XZIQcQgIkl/jheSUv5Du6p59zIzBkrFkr7u/+r6qrq6u7r1G+6tEOq2zZ+AK9cN52Dg+3/VYGYrzC74sw+35RRn5ZSjNr7e8pqx/cOzkUX4APjhWKFznUUB8qHGXvge9jesra7WFah1gWTgAcPIS3FP/7aSQEkHkCg9oBrpoSMzNIFuILPEuy0BthG6EGaCFQJU2ZQbyEVrzNltZLNbY7XyeZ7B8Yh9FL69nAG5YOQhDpJTvLLBgvreyRkv5eZwxWF4iGwbKdUgNlu+vYsDcLQgNlrMHLuZkdXMpS2paKIc1ZfSas6d2IORhHEJAWZy22qiqowHVy7GUnNUV47hZFqxLz2mDbFFQR8jlXZAcR75CYVrNnQMeAWnwDj2REV3TBw3WxlVNQg6UjTT8Tt31kDgUPjW6c0ZYLR0C0vMCb3so+g6dTSyK4r1PSGMHqp6QQHwfSBj6nkOkx5l4l8JdrVC89+GZHfg49iQuIYz4ZkQCmI4FBTXHGU67VLQlD1VoyodoxRJUhCyjeAFjGma/66lGliQnjGjH47EYaunoZk8pD34/I3TKCiUJn1BitCcPpeIYFRcWI0okBXIoVmR967wsUZ8qovbqxFFE2eEcd7TE8ZIA4USUMtHi8q32Eu1xK9MQdnnT86g/gdZMBZkGpmt1Ar3lMdMrt+Ig1JkzVSWg0QdGApq2xVP9kbZtUNlVQYNQ1eiTaEicFooGpNW+Q3uTxaT5uPWLPOwDcaTXSao4bYYbu0qETaotdc7s1h42yVrqMy215InQJ30xwbaqqpYdKgR4rKnvN30mgDDXRJlvOyUwOTpfi74XXuYkctN+cUeM97crhZ77ViG8X2wfmIXpBnHamUV6YzZzMK0W0lVKGTO84RZ04nWd6+MHC2EIC2q1NXX01R91ntOk9gQJj9ohWGb5wQT3li0R1ROoqyvs2vAVM6OKBVtQLLn+P19uowwzMAVYxnUtvUYdHrmp3Ka5GdYwoPHe3CJSHQLVHyPUNAEe4DrtAVvkaixadolpvIu4KtR82HgYGukGbVM1bqk9mxfPMiMN36QrWYkTuOm0qcuupF9WirDCqK4vp532bPElHmvBjEnVRGatlpmk0TgsEBV4USU43PQC+0IcGWLWSlW8KYeGWDbW9L08Twsj10d/nN68WqtfZS0aqdutTfti3s4VyEXYard8iD3oc2ABlGdUL6yE4Datibp3IjJBUq/bu4WTlwrLPaU2liAUlBpJ2jbOTOmZ2xNTDk45ybCDw04y3MbhdjLs4bCXDAU6wKQP9TbRhCTDSA9dc4v5HhvG1kWzvh1GNKTSw7bNQxphq1TfPFgc1DfUcusJC5eeypJNEcgp6GyLqAsbWDdDjh2CJ4DejVVR+/pAq77ov4fdxOoYr7ej10dt5cb6cr3gQRu2wC8wCCAGrtyo+t5/vqt+v4LBnz/BYO+Z/sTh3jM7qw1wtAvTb35+Odj9ZfD5w9ffP/jv1aPXjx7u/7VHfDl4+PjNq/uDvd/3X/44+PqbwR97gxdP/vn7xZsnj17vfjt4vGuIZTAMPIsTnAd7/97/zhidGAYMFwsmxsHTL4xP6//Lp8bD/vNfBz/8NrJ3oWkZtTtLK7euq48bq6P1q65o4d4s9OZGAAEBPQvZJ3fySE6eJCPjc5VZa3qVOTMVlzozqrU5qh5NkY0sz1fmMpYeUzWpvpeKkKquPbK9UDmdscXXcxwY25Fp8VylmA2h26LUPyCQ4vlKce4AxkRAY5QLleLpAygHxHWmcjZDiLhMHimb/tFr+X9FzcCRShAAAA==')

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