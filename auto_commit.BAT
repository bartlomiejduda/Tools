@echo off
:: Auto commit script 
:: by Bartlomiej Duda
:: Creation date: 12.03.2020
echo AUTO_COMMIT START
for /f "tokens=2 delims==" %%a in ('wmic OS Get localdatetime /value') do set "dt=%%a"
set "YY=%dt:~2,2%" & set "YYYY=%dt:~0,4%" & set "MM=%dt:~4,2%" & set "DD=%dt:~6,2%"
set "HH=%dt:~8,2%" & set "Min=%dt:~10,2%" & set "Sec=%dt:~12,2%"

set "datestamp=%YYYY%%MM%%DD%" & set "timestamp=%HH%%Min%%Sec%"
set "fullstamp=%DD%.%MM%.%YYYY% %HH%:%Min%"
git add .
git commit -m "Tools AUTO_COMMIT %fullstamp%"
git push
echo AUTO_COMMIT END
pause