import sys
from cx_Freeze import setup, Executable
from main import VERSION_NUM, EXE_FILE_NAME, PROGRAM_NAME

base = None
if sys.platform == "win32":
    base = "Console"


executables = [
    Executable(
        "main.py",
        copyright="Copyright (C) 2022 Bartlomiej Duda",
        base=base,
        icon="data/icon_bd.ico",
        target_name=EXE_FILE_NAME
    )
]

build_exe_options: dict = {
    "packages": [],
    'includes': [],
    "excludes": ["tkinter", "PIL", "PyQt4", "PyQt5"],
    'include_files': ['data/LICENSE', 'data/readme.txt'],
}

options: dict = {
    'build_exe': build_exe_options
}

setup(
    name=PROGRAM_NAME,
    version=VERSION_NUM[1:],
    description="Tool for modding Satellite Reign",
    options=options,
    executables=executables,
)
