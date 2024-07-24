@echo off
%~dp0\msdos -x %~dp0\psylibd.exe %*
exit /b %errorlevel%