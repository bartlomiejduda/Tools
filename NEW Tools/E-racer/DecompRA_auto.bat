
:: DecompRA AUTO script
:: It automates decompressing files
:: using DecompRA.exe program.

:: Copyright © 2020  Bart³omiej Duda
:: License: GPL-3.0 License 

:: Changelog:
:: Ver    Date        Name
:: v1.0   09.12.2020  Bartlomiej Duda

@ECHO OFF
echo DecompRA AUTO script by Bartlomiej Duda
echo Starting program...
echo.
echo.

setlocal enabledelayedexpansion
SET ra_directory="D:\INNE_GRY\eRacer DEMO\eRacer.xfs_OUT"


echo Starting loop...
for /f "tokens=* delims=" %%a in ('dir %ra_directory%\*.ra /s /b') do (
set ra_filename=%%a
echo !ra_filename!
set out_filename=!ra_filename:~0,-3!
echo !out_filename!
".\DecompRA.exe" "!ra_filename!" "!out_filename!"
del "!ra_filename!"
echo.
)

pause




