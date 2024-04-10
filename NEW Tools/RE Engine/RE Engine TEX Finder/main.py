"""
Copyright © 2024  Bartłomiej Duda
License: GPL-3.0 License
"""

import os
import struct

# Script for finding valid RE Engine TEX files


# globals
search_directory_path = os.environ["SEARCH_DIRECTORY"]
version_numbers_to_ignore = []
image_types_to_ignore = []
version_numbers_to_select = []
image_types_to_select = []
match_counter: int = 0
search_type: str = "ignore"  # ignore/select
found_versions = {}
found_image_types = {}


def parse_tex_file(source_tex_file_path: str, file_name: str) -> int:
    global version_numbers_to_ignore
    global version_numbers_to_select
    global image_types_to_ignore
    global image_types_to_select
    global match_counter
    global found_versions
    global found_image_types

    tex_file = None
    try:
        tex_file = open(source_tex_file_path, "rb")
        signature = tex_file.read(4).decode("utf8")
        if signature != "TEX\x00":
            print("[1] Invalid file signature --> ", source_tex_file_path)
            return -1
    except UnicodeDecodeError as error:
        tex_file.close()
        print("[2] Invalid file signature --> ", source_tex_file_path, " Error: ", error)
        return -1

    tex_file.seek(4)
    tex_version = struct.unpack("<I", tex_file.read(4))[0]
    tex_file.seek(16)
    image_type = struct.unpack("<I", tex_file.read(4))[0]

    if search_type == "ignore":
        if tex_version not in version_numbers_to_ignore and image_type not in image_types_to_ignore:
            print(f"FOUND MATCH -> img_name: {file_name}, tex_version: {tex_version}, image_type: {image_type}")
            match_counter += 1
            found_versions[tex_version] = True
            found_image_types[image_type] = True
    elif search_type == "select":
        if tex_version in version_numbers_to_select or image_type in image_types_to_select:
            print(f"FOUND MATCH -> img_name: {file_name}, tex_version: {tex_version}, image_type: {image_type}")
            match_counter += 1
            found_versions[tex_version] = True
            found_image_types[image_type] = True
    else:
        print("Wrong option!")
        return -1

    return 0


def find_tex_files():
    global search_directory_path
    for root, dirs, files in os.walk(search_directory_path):
        for file in files:
            file_extension = file.split(".")[-1].upper()
            if file_extension in ("35", "TEX"):
                file_abs_path = os.path.join(root, file)
                parse_tex_file(file_abs_path, file)

    print("Finished searching!")


if __name__ == "__main__":
    print("Initializing main...")
    find_tex_files()
    print(f"Matches found: {match_counter}")
    print(f"Found versions: {sorted(list(found_versions.keys()))}")
    print(f"Found image_types: {sorted(list(found_image_types.keys()))}")
    print(f"Search directory: {search_directory_path}")
