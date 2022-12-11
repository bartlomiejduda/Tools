"""
Copyright © 2022  Bartłomiej Duda
License: GPL-3.0 License
"""

# Program tested on Python 3.11

# Ver    Date        Author               Comment
# v0.1   04.12.2022  Bartlomiej Duda      -
# v0.2   06.12.2022  Bartlomiej Duda      -
import os
from dataclasses import dataclass
from typing import List, Optional

import lzokay

from reversebox.common.common import convert_int_to_hex_string
from reversebox.io_files.file_handler import FileHandler

from objects import HashEntryObject, DirectoryEntryObject

print("Starting HVP extract script...")

# cachpack.hvp - ZWO, DAT, HOE
# kinepack.hvp - BIK
# datapack.hvp - ZWO, DIC, XMC
# loadpack.hvp  - WAV, SUB, ZWO
hvp_path = "C:\\GRY\\Obscure 2\\kinepack.hvp"
hvp_handler = FileHandler(hvp_path, "rb")

hvp_handler.open()

known_hashes_counter: int = 0
all_hashes_list: List[HashEntryObject] = []
directory_entries: List[DirectoryEntryObject] = []

# read header
signature = hvp_handler.read_uint32()
if signature != 262144:
    print("It is not valid HVP file!")
    exit(0)
zero = hvp_handler.read_uint32()
number_of_entries = hvp_handler.read_uint32()
directory_crc32 = hvp_handler.read_uint32()


# read hash lists
for r, d, f in os.walk("hash_lists"):
    for file in f:
        if file.endswith(".txt"):
            hash_list_path = os.path.join(r, file)
            hash_list_file = open(hash_list_path, "rt")
            for line in hash_list_file:
                if line.startswith("#"):
                    continue

                crc_value, len_value, path_value = line.split("|||")
                all_hashes_list.append(HashEntryObject(
                    crc=int(crc_value, 16),
                    path_length=int(len_value),
                    file_path=str(path_value).rstrip('\n')
                ))


# read directory
for i in range(number_of_entries):
    crc_hash = hvp_handler.read_uint32()
    crc_hash_hex = convert_int_to_hex_string(crc_hash)
    entry_type = hvp_handler.read_uint32()
    value1 = hvp_handler.read_uint32()
    value2 = hvp_handler.read_uint32()
    value3 = hvp_handler.read_uint32()
    value4 = hvp_handler.read_uint32()

    entry_type_str = None
    if entry_type == 0:
        entry_type_str = "VID "
    if entry_type == 1:
        entry_type_str = "FILE"
    if entry_type == 4:
        entry_type_str = "DIR "

    matched_name: Optional[str] = None
    full_path: Optional[str] = None
    for hash_obj in all_hashes_list:
        if hash_obj.crc == crc_hash:
            matched_name = hash_obj.file_path[0:hash_obj.path_length]
            full_path = hash_obj.file_path
            known_hashes_counter += 1

    print(str(i) + ") ",
          #"hvp_hash=", crc_hash,
          "\thvp_hash_str=", crc_hash_hex,
          # "\te_type_INT=", entry_type,
          "\te_type=", entry_type_str,
          "\tmatched_name=", matched_name,
          #"\tfull_path=", full_path,
          # "\tval1=", value1,
          # "\tval2=", value2,
          # "\tval3=", value3,
          # "\tval4=", value4,
          )

    unknown_entry_name: str = "unknown_entry" + str(i)
    if entry_type == 1:  # file
        unknown_entry_name += ".bin"

    directory_entries.append(DirectoryEntryObject(
        entry_hash=crc_hash_hex,
        entry_name=matched_name if matched_name is not None else unknown_entry_name,
        entry_type=entry_type,
        value1=value1,
        value2=value2,
        value3=value3,
        value4=value4,
    ))


# recursive function for traversing through HVP directory
# to save files in proper output directories
def get_subentries(dir_entries: List[DirectoryEntryObject], entry_number: int, file_path: str, output_path: str):
    entry = dir_entries[entry_number]
    file_path += entry.entry_name
    if entry.entry_type == 4:
        file_path += "\\"
        current_entry_number: int = entry.value4
        for _ in range(entry.value3):
            get_subentries(dir_entries, current_entry_number, file_path, output_path)
            current_entry_number += 1
    if entry.entry_type in (0, 1):
        absolute_file_path = os.path.join(output_path, *file_path.split("\\"))
        absolute_dir_path = os.path.dirname(absolute_file_path)
        #print("FILE->", file_path)
        if not os.path.exists(absolute_dir_path):
            try:
                os.makedirs(absolute_dir_path)
            except FileNotFoundError:
                print("Can't create output directory! Exiting!")
                exit(1)
        hvp_handler.seek(entry.value3)
        file_data = hvp_handler.read_bytes(entry.value4)
        if entry.entry_type == 1:
            file_data = lzokay.decompress(file_data)
        output_file = open(absolute_file_path, "wb")
        output_file.write(file_data)
        output_file.close()


main_output_path = None  # TODO - add passing this as argument by cmd
if not main_output_path:
    main_output_path = hvp_path + "_out"
    if not os.path.exists(main_output_path):
        try:
            os.makedirs(main_output_path)
        except FileNotFoundError:
            print("Can't create output directory! Exiting!")
            exit(1)



get_subentries(directory_entries, 0, "", main_output_path)
hvp_handler.close()


print("== Stats for", hvp_path.split("\\")[-1], " ==")
print("All entries:", number_of_entries)
print("Known hashes:", known_hashes_counter)
print("Unknown hashes:", number_of_entries - known_hashes_counter)
progress = str(round(known_hashes_counter / number_of_entries * 100, 2)) + "%"
print("Hash progress:", progress)

print("Export script finished successfully!")
