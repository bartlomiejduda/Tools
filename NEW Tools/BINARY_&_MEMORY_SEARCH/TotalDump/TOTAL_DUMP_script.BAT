@echo off
:: Proc dump script 
:: by Bartlomiej Duda
:: Creation date: 03.08.2020
echo PROC DUMP START

set /p PID="Enter PID: "
TotalDump.exe %PID%
echo PROC DUMP END
pause