"""
Copyright © 2022  Bartłomiej Duda
License: GPL-3.0 License
"""

# Program tested on Python 3.11

# Ver    Date        Author               Comment
# v0.1   04.12.2022  Bartlomiej Duda      -
# v0.2   08.12.2022  Bartlomiej Duda      -


# This script reads all hashes generated by ObsCure 2 HOOK
# then it creates new sorted list without any duplicates

import os
from operator import attrgetter
from objects import HashDumpObject

print("Starting create hook list script...")
print("Please wait. It may take a few minutes.")

hash_objects_from_dump: list = []
crc_list: list = []
hash_list_without_duplicates: list = []
orig_list_counter: int = 0
new_list_counter: int = 0


# reading hashes from hash dump files (generated by ObsCure 2 Hook)
for r, d, f in os.walk("hash_dumps"):
    for file in f:
        if file.endswith(".txt"):
            print("Opening file ", file)
            hash_dump_path = os.path.join(r, file)
            hash_dump_file = open(hash_dump_path, "rt")
            for line in hash_dump_file:
                if line.startswith("#"):
                    continue

                line_entry = line.split("\t")

                hash_dump_obj = HashDumpObject(
                    crc=line_entry[0].split("=")[-1],
                    path_length=int(line_entry[1].split("=")[-1]),
                    file_path=line_entry[2].split("=")[-1].rstrip("\n"),
                )
                hash_objects_from_dump.append(hash_dump_obj)
                orig_list_counter += 1
            hash_dump_file.close()


# removing duplicates
print("Removing duplicates...")
for hash_object in hash_objects_from_dump:
    if hash_object.crc not in crc_list:
        hash_list_without_duplicates.append(hash_object)
        new_list_counter += 1
    crc_list.append(hash_object.crc)


# sorting list by CRC32 value
print("Sorting list...")
hash_list_without_duplicates: list[HashDumpObject] = sorted(hash_list_without_duplicates, key=attrgetter('crc'))


output_file = open("hash_lists/obscure_2_hook_list.txt", "wt")

for hash_clean_entry in hash_list_without_duplicates:
    out_line = "0x" + hash_clean_entry.crc + "|||" + str(hash_clean_entry.path_length) \
               + "|||" + hash_clean_entry.file_path + "\n"
    output_file.write(out_line)

output_file.close()

print("OLD hash count: ", orig_list_counter)
print("NEW hash count: ", new_list_counter)
print("CREATE HOOK LIST SCRIPT EXECUTED SUCCESSFULLY!")
