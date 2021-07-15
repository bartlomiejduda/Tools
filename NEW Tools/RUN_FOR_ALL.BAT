
:: BAT script for quickbms.exe

:: Ver    Date        Name
:: v0.1   15.07.2021  Bartlomiej Duda


echo Starting batch processing...
echo.
echo.

for %%f in (.\*.gim) do ( 
.\quickbms.exe gim_script.bms "%%f" .\
)

echo BAT script has finished!
pause