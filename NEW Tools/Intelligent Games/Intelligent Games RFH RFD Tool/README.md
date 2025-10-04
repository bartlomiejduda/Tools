# Intelligent Games RFH RFD Tool
Tool for extracting/importing data from/to RFH/RFD archives.
RFH/RFD file format description can be found on [RE Wiki](https://rewiki.miraheze.org/wiki/Intelligent_Games_RFH_RFD).

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
   - ```python rfh_rfd_tool.py <arguments>```
   
   
## Usage

<pre>
Intelligent Games RFH/RFD Tool v1.0

options:
  -h, --help            show this help message and exit
  -e rfh_file_path rfd_file_path output_directory, --export rfh_file_path rfd_file_path output_directory
                        Export from RFH/RFD file
</pre>
