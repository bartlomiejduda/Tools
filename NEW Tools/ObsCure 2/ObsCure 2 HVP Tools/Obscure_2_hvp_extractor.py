"""
Copyright © 2022  Bartłomiej Duda
License: GPL-3.0 License
"""

# Program tested on Python 3.11

# Ver    Date        Author               Comment
# v0.1   04.12.2022  Bartlomiej Duda      -
from dataclasses import dataclass
from typing import List, Optional

from reversebox.common.common import convert_int_to_hex_string
from reversebox.io_files.file_handler import FileHandler
print("Starting HVP extract script...")

# cachpack.hvp
# kinepack.hvp
# datapack.hvp
# loadpack.hvp
hvp_path = "C:\\GRY\\Obscure 2\\loadpack.hvp"
hvp_handler = FileHandler(hvp_path, "rb")

hvp_handler.open()


# read header
signature = hvp_handler.read_uint32()
if signature != 262144:
    print("It is not valid HVP file!")
    exit(0)
zero = hvp_handler.read_uint32()
number_of_entries = hvp_handler.read_uint32()
directory_crc32 = hvp_handler.read_uint32()


@dataclass
class HashCleanListObject:
    crc: int
    path_length: int
    file_path: str


all_hashes_list: List[HashCleanListObject] = []


# read hash lists
hash_list_file = open("obscure_2_hash_clean_list.txt", "rt")
for line in hash_list_file:
    if line.startswith("#"):
        continue

    crc_value, len_value, path_value = line.split("|||")
    all_hashes_list.append(HashCleanListObject(
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

    print("hvp_hash=", crc_hash,
          "\thvp_hash_str=", crc_hash_hex,
          "\tmatched_filename=", matched_filename,
          #"\tfull_path=", full_path
          )


# TODO

print("Export script finished!")
