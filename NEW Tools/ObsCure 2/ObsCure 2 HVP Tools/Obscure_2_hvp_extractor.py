"""
Copyright © 2022  Bartłomiej Duda
License: GPL-3.0 License
"""

# Program tested on Python 3.11

# Ver    Date        Author               Comment
# v0.1   04.12.2022  Bartlomiej Duda      -
# v0.2   06.12.2022  Bartlomiej Duda      -
# v0.3   12.12.2022  Bartlomiej Duda      -
# v0.4   19.12.2022  Bartlomiej Duda      Added argparse


import argparse
import os
import sys
from typing import List, Optional
import lzokay
from reversebox.common.common import convert_int_to_hex_string
from reversebox.io_files.file_handler import FileHandler
from objects import HashEntryObject, DirectoryEntryObject, RepackInfoObject


def export_data(hvp_path: str) -> Optional[tuple]:
    """
    Function for exporting data
    """

    print("Starting HVP extract script...")

    # For debug only:
    # hvp_path = "C:\\GRY\\Obscure 2\\cachpack.hvp"
    # hvp_path = "C:\\Users\\Lenovo\\Desktop\\Obscure_2_RESEARCH\\PS2_HVP\\MIH_EN.HVP"
    # hvp_path = "C:\\Users\\Lenovo\\Desktop\\Obscure_2_RESEARCH\\PSP_HVP\\loadpack.hvp"

    hvp_handler = FileHandler(hvp_path, "rb")

    try:
        hvp_handler.open()
    except FileNotFoundError:
        print("Error! Invalid file path: ", hvp_path)
        exit(-1)

    known_hashes_counter: int = 0
    all_hashes_list: List[HashEntryObject] = []
    directory_entries: List[DirectoryEntryObject] = []
    repack_info_list: List[RepackInfoObject] = []

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
            entry_type_str = "FILE0"
        elif entry_type == 1:
            entry_type_str = "FILE1"
        elif entry_type == 4:
            entry_type_str = "DIR_4"
        else:
            entry_type_str = "UNK  "

        matched_name: Optional[str] = None
        full_path: Optional[str] = None
        for hash_obj in all_hashes_list:
            if hash_obj.crc == crc_hash:
                matched_name = hash_obj.file_path[0:hash_obj.path_length]
                full_path = hash_obj.file_path
                known_hashes_counter += 1

        print(str(i) + ") ",
              "\thvp_hash_str=", crc_hash_hex,
              "\te_type=", entry_type_str,
              "\tmatched_name=", matched_name,
              "\tval1=", convert_int_to_hex_string(value1),
              )

        unknown_entry_name: str = "unknown_entry" + str(i)
        if entry_type in (0, 1):  # asset or video
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
        # repack_info_list.append(RepackInfoObject(
        #     entry_hash=entry.entry_hash,
        #     entry_name=entry.entry_name,
        #     entry_val1=convert_int_to_hex_string(entry.value1),
        #     entry_type=entry.entry_type
        # ))
        if entry.entry_type == 4:
            file_path += "\\"
            current_entry_number: int = entry.value4
            for _ in range(entry.value3):
                get_subentries(dir_entries, current_entry_number, file_path, output_path)
                current_entry_number += 1
        if entry.entry_type in (0, 1):
            absolute_file_path = os.path.join(output_path, *file_path.split("\\"))
            absolute_dir_path = os.path.dirname(absolute_file_path)
            # print("FILE->", file_path)
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

    main_output_path = None
    if not main_output_path:
        main_output_path = hvp_path + "_out"
        if not os.path.exists(main_output_path):
            try:
                os.makedirs(main_output_path)
            except FileNotFoundError:
                print("Can't create output directory! Exiting!")
                exit(1)

    print("Extracting data...")
    print("Please wait. It may take a while.")
    get_subentries(directory_entries, 0, "", main_output_path)
    hvp_handler.close()

    # print("Generating repack info...")
    # repack_info_file_path = hvp_path + "_repack_info.txt"
    # repack_info_file = open(repack_info_file_path, "wt")
    # for repack_entry in repack_info_list:
    #     out_line = repack_entry.entry_hash + \
    #                "|||" + str(repack_entry.entry_type) + \
    #                "|||" + repack_entry.entry_val1 + \
    #                "|||" + repack_entry.entry_name + "\n"
    #     repack_info_file.write(out_line)
    # repack_info_file.close()

    print("== Stats for", hvp_path.split("\\")[-1], " ==")
    print("All entries:", number_of_entries)
    print("Known hashes:", known_hashes_counter)
    print("Unknown hashes:", number_of_entries - known_hashes_counter)
    hash_progress = str(round(known_hashes_counter / number_of_entries * 100, 2)) + "%"
    print("Hash progress:", hash_progress)

    print("")
    print("Data extracted to", main_output_path, "directory.")
    return "OK", ""


VERSION_NUM = "v1.0"
EXE_FILE_NAME = f"obscure_2_hvp_extractor_{VERSION_NUM}.exe"
PROGRAM_NAME = f'Obscure 2 HVP Extractor {VERSION_NUM}'


def main():
    """
    Main function of this program.
    """
    parser = argparse.ArgumentParser(prog=EXE_FILE_NAME,
                                     description=PROGRAM_NAME)
    # fmt: off
    parser.add_argument('-e', '--ext', metavar='<hvp_file_path>',
                        type=str, nargs=1, required=False, help='Extract data from HVP archives')
    # fmt: on

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    if args.ext is not None:
        code, status = export_data(args.ext[0])
        if code != "OK":
            print(f"{code}: {status}")
            sys.exit(-1)

    print("End of main... Program has been executed successfully!")
    sys.exit(0)


if __name__ == "__main__":
    main()
