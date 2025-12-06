@echo off
call "%~dp0msdos" -x "%~dp0psylibd.exe" %*
exit /b %errorlevel%
