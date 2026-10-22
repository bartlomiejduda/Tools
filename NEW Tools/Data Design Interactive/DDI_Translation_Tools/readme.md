## Data Design Interactive Translation Tools

Set of tools for translating Data Design Interactive games. (WORK IN PROGRESS)

Tested on following games:
 - Anubis II (PC) (WORK IN PROGRESS)


### WAD Tool
Tool for handling export and import from WAD archives

wad_tool.py --extract file.WAD output_directory
wad_tool --import output_directory file.WAD


### CFB Tool
Tool for handling translation text from binary config files. 

cfb_tool.py --extract input_directory output.INI
cfb_tool --import output.INI input_directory


### Character replacer
Tool for replacing characters in translated texts to mapped characters.

char_replacer.py input_directory
