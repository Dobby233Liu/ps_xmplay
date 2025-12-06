@echo off
setlocal enabledelayedexpansion

set "files="
set "opts="

for %%i in (%*) do (
    if "%%~i"=="-v" (
        set "opts=!opts! -v"
    ) else if "%%~i"=="-n" (
        set "opts=!opts! -n"
    ) else (
        set "files=!files! "%%~i""
    )
)

set lastel=0
for %%i in (%files%) do (
    pushd %%~dpi || goto :fail
    call "%~dp0..\..\psyq\bin\msdos" "%~dp0vabsplit.exe" %opts% %%~nxi
    set lastel=!errorlevel!
    popd
    if !lastel! neq 0 goto :fail
)

:fail
exit /b %lastel%
