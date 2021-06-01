
:: BAT script for RTPack.exe
:: It automates font creation.

:: Ver    Date        Name
:: v0.1   27.05.2021  Bartlomiej Duda

@ECHO OFF
echo Dink Smallwood BAT script by Bartlomiej Duda
echo Starting batch processing...
echo.
echo.

setlocal enabledelayedexpansion

for %%f in (.\IN\*.txt) do ( 
.\RTPack.exe -make_font "%%f"
)

echo .
echo .
echo START MOVING
for %%f in (.\IN\*.rtfont) do ( 

set out_path1=%%f
set out_path2=.\OUT\!out_path1:~5!
echo !out_path2!
move "%%f" !out_path2!
)


echo .
echo .
echo START DELETING
for %%f in (.\IN\*.rttex) do ( 
del "%%f"
echo Deleted "%%f"...
)

del log.txt

echo BAT script has finished!
pause

