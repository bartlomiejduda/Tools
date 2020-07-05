@echo off
:: Make EXE script 
:: by Bartlomiej Duda
:: Creation date: 05.07.2020
set PYTHONOPTIMIZE=1 && pyinstaller -F -i ..\files\icon_bd.ico --upx-dir c:\upx\ ..\BDTexView.pyw
move Dist\BDTexView.exe ..\BDTexView.exe 
rmdir /S /Q "dist"
rmdir /S /Q "build"
rmdir /S /Q "..\__pycache__"
del BDTexView.spec
pause