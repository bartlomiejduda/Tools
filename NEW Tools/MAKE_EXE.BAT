
:: BAT script for making exe with g++

:: Ver    Date        Name
:: v0.1   02.08.2021  Bartlomiej Duda

@ECHO OFF
echo Starting make...
echo.
echo.

setlocal enabledelayedexpansion

set g_path=C:\Program Files\CodeBlocks\MinGW\bin\g++.exe



echo STEP 1
"!g_path!" -c DXArchive.cpp -o DXArchive.o
echo STEP 2
"!g_path!" -c DXArchiveDecode.cpp -o DXArchiveDecode.o
echo STEP 3
"!g_path!" -c FileLib.cpp -o FileLib.o
echo STEP 4
"!g_path!" -w -fpermissive -c DXArchiveVer5.cpp -o DXArchiveVer5.o
echo STEP 5 
"!g_path!" -static -static-libgcc -static-libstdc++ DXArchiveDecode.o DXArchive.o DXArchiveVer5.o FileLib.o -o DXArchiveDecode.exe




echo Ending make...
pause