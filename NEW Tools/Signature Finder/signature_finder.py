"""
Copyright © 2023  Bartłomiej Duda
License: GPL-3.0 License
"""

import os
import shutil

# Script for finding valid files with specified signature
# Works great with aluigi's comptype scanner


# globals (those need to be adjusted for each run)
search_directory_path = os.environ["SEARCH_DIRECTORY"]
copy_directory_path = os.environ["COPY_DIRECTORY"]
copy_allowed: bool = True
change_extension_allowed: bool = True
original_extension: str = ".dmp"
new_extension: str = ".bmp"
signature_to_find: bytes = b'BM'
seek_offset: int = 0


def parse_binary_file(source_file_path: str, file_name: str) -> int:
    global signature_to_find
    global seek_offset
    global copy_directory_path
    global copy_allowed
    global change_extension_allowed
    global original_extension
    global new_extension
    binary_file = None
    try:
        binary_file = open(source_file_path, "rb")
        binary_file.seek(seek_offset)
        signature = binary_file.read(len(signature_to_find))
        if signature == signature_to_find:
            print("File found! --> ", file_name)
            if copy_allowed:
                if change_extension_allowed:
                    file_name = file_name.replace(original_extension, new_extension)
                    print("New filename: " + str(file_name))
                copy_file_path = os.path.join(copy_directory_path, file_name)
                shutil.copyfile(source_file_path, copy_file_path)
            return -1
    except Exception:
        binary_file.close()
        return -1

    return 0


def find_binary_files():
    print("Start searching...")
    global search_directory_path

    for root, dirs, files in os.walk(search_directory_path):
        for file in files:
            # file_extension = file.split(".")[-1].upper()
            # if file_extension == ".bin":

            file_abs_path = os.path.join(root, file)
            parse_binary_file(file_abs_path, file)

    print("Finished searching!")


if __name__ == "__main__":
    find_binary_files()
