"""
Copyright © 2022  Bartłomiej Duda
License: GPL-3.0 License
"""

# Program tested on Python 3.11

# Ver    Date        Author               Comment
# v0.1   06.12.2022  Bartlomiej Duda      -
from operator import attrgetter
from typing import List

from reversebox.common.common import convert_int_to_hex_string
from reversebox.checksum import checksum_crc32_iso_hdlc
crc32_handler = checksum_crc32_iso_hdlc.CRC32Handler()

from custom_hashes import CUSTOM_HASHES
from objects import HashEntryObject

custom_hash_list: List[HashEntryObject] = []
clean_hash_list: List[HashEntryObject] = []


print("Starting to create custom hash list...")


# read clean hash list (to check for duplicates)
clean_hash_file = open("hash_lists\obscure_2_hash_clean_list.txt", "rt")
for line in clean_hash_file:
    if line.startswith("#"):
        continue

    crc_value, len_value, path_value = line.split("|||")
    clean_hash_list.append(HashEntryObject(
        crc=int(crc_value, 16),
        path_length=int(len_value),
        file_path=str(path_value).rstrip('\n')
    ))


# add entries to custom hash list
# (also check for issues, e.g. duplicates, wrong length etc.)
for custom_hash_entry in CUSTOM_HASHES:
    for clean_hash_entry in clean_hash_list:
        if custom_hash_entry.crc == clean_hash_entry.crc:
            raise Exception(f"Duplicate CRC = {convert_int_to_hex_string(custom_hash_entry.crc)}"
                            f" for path {custom_hash_entry.file_path}! Please remove it!")

    calculated_crc = crc32_handler.calculate_crc32(
        bytes(custom_hash_entry.file_path.encode("utf8")[0:custom_hash_entry.path_length]))
    if calculated_crc != custom_hash_entry.crc:
        raise Exception("Wrong CRC value! Please correct it!")

    if custom_hash_entry.path_length < 0 or custom_hash_entry.path_length > len(custom_hash_entry.file_path):
        raise Exception("Wrong string length! Please correct it!")

    custom_hash_list.append(custom_hash_entry)


# sorting output list
custom_hash_list: list[HashEntryObject] = sorted(custom_hash_list, key=attrgetter('crc'))

# write results to file if no exception occurred at checking phase
custom_hash_file = open("hash_lists\obscure_2_custom_hash_list.txt", "wt")
for custom_entry in custom_hash_list:
    out_line: str = convert_int_to_hex_string(custom_entry.crc) + "|||" + str(custom_entry.path_length) + "|||" + custom_entry.file_path + "\n"
    custom_hash_file.write(out_line)

print("Custom hash list has been created successfully!")
