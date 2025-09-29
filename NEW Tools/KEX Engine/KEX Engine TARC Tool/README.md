# KEX Engine TARC Tool
Tool for extracting/importing data from/to TARC archives.
TARC file format description can be found on [RE Wiki](https://rewiki.miraheze.org/wiki/KEX_Engine_TARC).

## Dependencies

* **[ReverseBox](https://github.com/bartlomiejduda/ReverseBox)**


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
6. Run the main script file
   - ```python kex_engine_tarc_tool.py <arguments>```
   
   
# Usage

<pre>
KEX Engine TARC Tool v1.0

options:
  -h, --help            show this help message and exit
  -e tarc_file_path output_directory, --export tarc_file_path output_directory
                        Export from TARC file
  -i input_directory tarc_file_path, --import input_directory tarc_file_path
                        Import to TARC file
</pre>
