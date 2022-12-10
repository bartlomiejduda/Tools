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

from reversebox.common.common import convert_int_to_hex_string
from reversebox.io_files.file_handler import FileHandler

from objects import HashEntryObject

print("Starting HVP extract script...")

# cachpack.hvp
# kinepack.hvp - BIK
# datapack.hvp - ZWO, DIC, XMC
# loadpack.hvp  - WAV
hvp_path = "C:\\GRY\\Obscure 2\\cachpack.hvp"
hvp_handler = FileHandler(hvp_path, "rb")

hvp_handler.open()

known_hashes_counter: int = 0
all_hashes_list: List[HashEntryObject] = []

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
#hvp_handler.change_endianess("big")
for i in range(number_of_entries):
    crc_hash = hvp_handler.read_uint32()
    crc_hash_hex = convert_int_to_hex_string(crc_hash)
    dummy = hvp_handler.read_bytes(20)

    matched_filename: Optional[str] = None
    full_path: Optional[str] = None
    for hash_obj in all_hashes_list:
        if hash_obj.crc == crc_hash:
            matched_filename = hash_obj.file_path[0:hash_obj.path_length]
            full_path = hash_obj.file_path
            known_hashes_counter += 1

    print("hvp_hash=", crc_hash,
          "\thvp_hash_str=", crc_hash_hex,
          "\tmatched_filename=", matched_filename,
          #"\tfull_path=", full_path
          )


print("== Stats for ", hvp_path.split("\\")[-1], " ==")
print("All entries: ", number_of_entries)
print("Known hashes: ", known_hashes_counter)
print("Unknown hashes: ", number_of_entries - known_hashes_counter)
progress = str(round(known_hashes_counter / number_of_entries * 100, 2)) + "%"
print("Progress: ", progress)

print("Export script finished!")
