
:: FSB BATCH GENERATOR
:: It generates FSB files from WAV files using FMOD Designer command line tool.

:: Ver    Date        Name
:: v1.0   19.07.2019  Bartlomiej Duda
:: v1.1   20.07.2019  Bartlomiej Duda

@ECHO OFF
echo FSB BATCH GENERATOR by Bartlomiej Duda
echo Starting program...
echo.
echo.

SET fdp_filename=NOWY_5.fdp
setlocal enabledelayedexpansion

for %%f in (.\IN\*.wav) do ( 
echo %%f
".\Line_Replacer.exe" "%fdp_filename%" filename "<filename>%%f</filename>"
".\fmod_designercl.exe" -pc "%fdp_filename%"
SET fsb_bank=.\!fdp_filename:~0,-4!_bank00.fsb
set file_name=%%f
set file_name_trim=!file_name:~5!
set file_name_trim2=!file_name_trim:~0,-4!.fsb
SET out_path=.\OUT\!file_name_trim2!
echo !fsb_bank!
echo !out_path!
move "!fsb_bank!" "!out_path!"

)

echo Program has finished!
pause

