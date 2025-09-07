# Room Of Prey VFS Tool

# Info

This tool was designed to extract and import data 
from/to VFS archives from "Room Of Prey" Android game series.

## How to Build on Windows

1. Download and install  **[Python 3.11.6](https://www.python.org/downloads/release/python-3116/)**. Remember to add Python to PATH during installation
2. Download project's source code and unpack it
3. Go to the directory containing source code
   - ```cd <directory_path>```
4. Create virtualenv and activate it
   - ```python -m venv my_env```
   - ```.\my_env\Scripts\activate.bat```
5. Install all libraries from requirements.txt file
   - ```pip install -r requirements.txt```
6. Add project's directory to PYTHONPATH environment variable
   - ```set PYTHONPATH=C:\Users\user\Desktop\ImageHeat-master```
7. Run the main script file
   - ```python Room_Of_Prey_VFS_Tool.py```
   
   
# Usage

<pre>
Room Of Prey VFS Tool v1.0

options:
  -h, --help            show this help message and exit
  -e vfs_file_path output_directory_path, --export vfs_file_path output_directory_path
                        Export from VFS file
  -i input_directory_path vfs_file_path, --import input_directory_path vfs_file_path
                        Import to VFS file
</pre>
