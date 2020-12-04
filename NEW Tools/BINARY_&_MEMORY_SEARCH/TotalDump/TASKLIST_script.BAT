@echo off
:: Tasklist script 
:: by Bartlomiej Duda
:: Creation date: 03.08.2020
echo TASKLIST START

tasklist | findstr /R /C:"OVERLAY" 

@echo off
echo TASKLIST END
pause