"""
Copyright © 2023  Bartłomiej Duda
License: GPL-3.0 License
"""

import os
import struct
import shutil

# Script for finding valid ITF files


# globals
search_directory_path = os.environ["SEARCH_DIRECTORY"]
copy_directory_path = os.environ["COPY_DIRECTORY"]
allowed_chunk_types = (10,)
summary_dict = {}


def parse_itf_file(source_itf_file_path: str, file_name: str) -> int:
    global copy_directory_path
    global summary_dict
    itf_file = None
    try:
        itf_file = open(source_itf_file_path, "rb")
        signature = itf_file.read(4).decode("utf8")
        if signature != "FORM":
            print("Invalid file signature --> ", source_itf_file_path)
            return -1
    except UnicodeDecodeError as error:
        itf_file.close()
        print("Invalid file signature --> ", source_itf_file_path, " Error: ", error)
        return -1

    itf_file.seek(23)
    chunk_type = struct.unpack("B", itf_file.read(1))[0]

    entry_count = summary_dict.get(str(chunk_type), 0)
    entry_count += 1
    summary_dict[str(chunk_type)] = entry_count

    if chunk_type in allowed_chunk_types:
        print("File_name: " + str(file_name) + " chunk_type: " + str(chunk_type))
        copy_file_path = os.path.join(copy_directory_path, file_name)
        shutil.copyfile(source_itf_file_path, copy_file_path)
    return 0


def find_itf_files():
    global search_directory_path
    global summary_dict
    for root, dirs, files in os.walk(search_directory_path):
        for file in files:
            file_extension = file.split(".")[-1].upper()
            if file_extension == "ITF":
                file_abs_path = os.path.join(root, file)
                parse_itf_file(file_abs_path, file)

    print("Summary: " + str(summary_dict))
    print("Finished searching!")
    print("All files copied to " + str(copy_directory_path))


if __name__ == "__main__":
    find_itf_files()
