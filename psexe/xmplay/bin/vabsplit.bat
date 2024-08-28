@echo off

shift
pushd "%~dp0"
set x=
for %%i in ("%*") do (
shift
set "x=%x% %~nx0"
)
call :vabsplit %x%
set el=%errorlevel%
popd
exit /b %lastel%

:vabsplit
call "%~dp0..\..\psyq\bin\msdos" "%~dp0vabsplit.exe" %*
exit /b %errorlevel%