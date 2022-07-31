@echo off
cls
fd -a --exact-depth 1 --search-path "%~dp0Lib\file_templete" | peco --rcfile D:\tools\bin\peco.cfg | clip.exe
@echo on