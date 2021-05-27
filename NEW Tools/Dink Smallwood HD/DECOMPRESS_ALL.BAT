
:: BAT script for Dink Smallwood HD Text Tool
:: It automates text decompressing.

:: Ver    Date        Name
:: v0.1   26.05.2021  Bartlomiej Duda

@ECHO OFF
echo Dink Smallwood BAT script by Bartlomiej Duda
echo Starting batch processing...
echo.
echo.

setlocal enabledelayedexpansion

for %%f in (.\IN\*.d) do ( 
echo %%f

set out_path=%%f
set out_path2=!out_path:~5!
set out_path3=.\OUT\!out_path2!
set out_path4=!out_path3:~0,-2!.c
echo !out_path4!

".\dink_smallwood_hd_text_tool.exe" "%%f" !out_path4!


)

echo BAT script has finished!
pause

