# Obscure 2 HVP Tools

## Prerequisites

You need following Python packages to work with those tools:
- ReverseBox v0.3.1
- lzokay v1.1.2

You can install them using those commands:
```
pip install ReverseBox==0.3.1
pip install lzokay==1.1.2
```

## Script for creating hook list

This script should be used only to process hash dump
created by "Obscure 2 Hook".

How to use it:
1. Place "obscure_2_hash_dump.txt" in the "hash_dumps" directory
2. Run "create_hook_list.py" script in Python

## Script for creating custom hash list

This script should be used only if you want to add new
hashes to the custom hash list.

How to use it:
1. Open "custom_filenames.py" Python script
2. Add you new names to the end of this file
3. Run "create_custom_hash_list.py" Python script
4. New hashes should be added to the 
"obscure_2_custom_hash_list.txt" file


## Obscure 2 HVP Extractor

This tool was designed to extract data from HVP archives.
It uses previously generated hash lists to match them
with the entries from HVP directory structure.
Once it's done, it uses recursive function to extract and
decompress files with the proper filenames and then it saves
them in the proper directories on your hard drive.

How to use it:
- TODO
