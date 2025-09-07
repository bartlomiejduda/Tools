"""
Copyright © 2025  Bartłomiej Duda
License: GPL-3.0 License
"""

# Program tested on Python 3.11

# Ver    Date        Author               Comment
# v1.0   07.09.2025  Bartlomiej Duda      -


import argparse
import os
import sys
from dataclasses import dataclass
from typing import List
from reversebox.common.logger import get_logger
from reversebox.hash.hash_djb2 import DJB2Handler
from reversebox.io_files.file_handler import FileHandler


logger = get_logger(__name__)


@dataclass
class HashEntryObject:
    crc: int
    file_path: str


def export_data(vfs_file_path: str, output_directory_path: str) -> None:
    """
    Function for exporting data
    """
    logger.info("Starting export_data...")

    vfs_handler = FileHandler(vfs_file_path, "rb")
    vfs_handler.open()

    all_hashes_list: List[HashEntryObject] = []
    djb2_handler: DJB2Handler = DJB2Handler()

    # read hash lists
    for r, d, f in os.walk("hash_lists"):
        for file in f:
            if file.endswith(".txt"):
                hash_list_path = os.path.join(r, file)
                hash_list_file = open(hash_list_path, "rt", encoding="utf8")
                for line in hash_list_file:
                    if line.startswith("#"):
                        continue

                    path_value = line.rstrip("\n")
                    crc_value = djb2_handler.calculate_djb2_hash_from_string(path_value, hash_size=4)
                    all_hashes_list.append(HashEntryObject(
                        crc=crc_value,
                        file_path=path_value
                    ))

    # remove duplicates
    all_hashes_list = list({obj.crc: obj for obj in all_hashes_list}.values())

    # extract data
    counter: int = 0
    archive_size: int = vfs_handler.get_file_size()
    while 1:
        counter += 1
        file_hash: int = vfs_handler.read_uint32()
        file_size: int = vfs_handler.read_uint32()
        file_data: bytes = vfs_handler.read_bytes(file_size)
        file_path: str = "file_" + str(counter) + ".bin"

        # try to get real file path
        for hash_entry in all_hashes_list:
            if hash_entry.crc == file_hash:
                file_path = hash_entry.file_path
                break

        logger.info(f"Extracting {file_path}...")

        file_path = os.path.join(output_directory_path, file_path)
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        output_file = open(file_path, "wb")
        output_file.write(file_data)
        output_file.close()

        if vfs_handler.get_position() == archive_size:
            break

    logger.info("All files extracted successfully!")


VERSION_NUM = "v1.0"
EXE_FILE_NAME = f"room_of_prey_vfs_tool_{VERSION_NUM}.exe"
PROGRAM_NAME = f'Room Of Prey VFS Tool {VERSION_NUM}'


def main():
    """
    Main function of this program.
    """

    parser = argparse.ArgumentParser(prog=EXE_FILE_NAME, description=PROGRAM_NAME)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-e", "--export", nargs=2, metavar=("vfs_file_path", "output_directory_path"), help="Export from VFS file")
    group.add_argument("-i", "--import", nargs=2, metavar=("input_directory_path", "vfs_file_path"), help="Import to VFS file")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    logger.info(f"Running {PROGRAM_NAME}...")

    if getattr(args, "export"):
        vfs_file_path, output_directory_path = getattr(args, "export")
        if not os.path.isfile(vfs_file_path):
            logger.error(f"[ERROR] File does not exist: {vfs_file_path}")
            sys.exit(1)
        if not os.path.isdir(output_directory_path):
            logger.error(f"[ERROR] Directory does not exist: {output_directory_path}")
            sys.exit(1)
        export_data(vfs_file_path, output_directory_path)

    elif getattr(args, "import"):
        input_directory_path, vfs_file_path = getattr(args, "import")
        if not os.path.isfile(vfs_file_path):
            logger.error(f"[ERROR] File does not exist: {vfs_file_path}")
            sys.exit(1)
        if not os.path.isdir(input_directory_path):
            logger.error(f"[ERROR] Directory does not exist: {input_directory_path}")
            sys.exit(1)
        # TODO - import function
        raise Exception("Not supported yet!")
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
