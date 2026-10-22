## Data Design Interactive Translation Tools

Set of tools for translating Data Design Interactive games. (WORK IN PROGRESS)

Tested on following games:
 - Anubis II (PC) (WORK IN PROGRESS)


### WAD Tool
Tool for handling export and import from WAD archives

wad_tool.py --extract file.WAD output_directory
wad_tool --import output_directory file.WAD


### CFB/CFG Converter
Tool for converting from CFB to CFG and from CFG to CFB

cfb_cfg_converter.py --to-binary file.CFG file.CFB
cfb_cfg_converter.py --to-text file.CFB file.CFG


### CFG Tool
Tool for handling translation text from CFG config files. 

cfg_tool.py --extract input_directory output.INI
cfg_tool --import output.INI input_directory


### Character replacer
Tool for replacing characters in translated texts to mapped characters.

char_replacer.py input_directory
