"""
Copyright © 2025  Bartłomiej Duda
License: GPL-3.0 License
"""
import argparse
import os
import sys
import zlib
from dataclasses import dataclass
from typing import Optional

from reversebox.common.logger import get_logger
from reversebox.crc.crc32_iso_hdlc import CRC32Handler
from reversebox.encryption.encryption_hatch_engine import decrypt_hatch_data
from reversebox.io_files.file_handler import FileHandler


logger = get_logger(__name__)

crc_handler = CRC32Handler()


# Entry for filename from TXT file and for calculated CRC value
@dataclass
class KnownCRCEntry:
    crc32: int
    file_name: str


def export_data(hatch_file_path: str, filenames_list_file_path: str, output_directory_path: str) -> bool:
    """
    Function for exporting data
    """
    logger.info("Starting export data...")
    known_filenames_counter: int = 0

    # Input parameters checks
    logger.info("Checking input parameters...")
    if not os.path.isfile(hatch_file_path) or os.path.getsize(hatch_file_path) <= 0:
        logger.error("Invalid HATCH file path provided! Exiting!")
        return False

    if not os.path.isfile(filenames_list_file_path) or os.path.getsize(filenames_list_file_path) <= 0:
        logger.error("Invalid FILENAME file path provided! Exiting!")
        return False

    if not os.path.isdir(output_directory_path):
        logger.error(f"Invalid output directory path! Exiting!")
        return False

    # Reading names from TXT file
    filenames_file = open(filenames_list_file_path, "rt")
    known_crc_entries_list: list[KnownCRCEntry] = []

    for line in filenames_file:
        f_filename: str = line.strip()
        f_crc: int = crc_handler.calculate_crc32(f_filename.encode("ascii"))
        crc_entry: KnownCRCEntry = KnownCRCEntry(
            crc32=f_crc,
            file_name=f_filename
        )
        known_crc_entries_list.append(crc_entry)
    filenames_file.close()

    # Parsing Hatch Archive
    hatch_file = FileHandler(hatch_file_path, "rb")
    signature = hatch_file.read_str(5, "utf8")

    if signature != "HATCH":
        raise Exception("Invalid Hatch Engine file!")

    version: bytes = hatch_file.read_bytes(3)
    file_count: int = hatch_file.read_uint16()

    for i in range(file_count):
        f_crc: int = hatch_file.read_uint32()
        f_offset: int = hatch_file.read_uint64()
        f_uncompressed_size: int = hatch_file.read_uint64()
        f_data_flag: int = hatch_file.read_uint32()
        f_compressed_size: int = hatch_file.read_uint64()
        f_filename: Optional[str] = f"Unknown_Files/file{i}.bin"
        back_offset: int = hatch_file.get_position()

        for known_crc_entry in known_crc_entries_list:
            if known_crc_entry.crc32 == f_crc:
                f_filename = known_crc_entry.file_name
                known_filenames_counter += 1
                break

        logger.info(f'{i}) {f_filename}')

        hatch_file.seek(f_offset)

        # Decompression logic
        if f_compressed_size != f_uncompressed_size:
            f_data: bytes = hatch_file.read_bytes(f_compressed_size)
            f_data = zlib.decompress(f_data)
        else:
            f_data: bytes = hatch_file.read_bytes(f_uncompressed_size)

        # Decryption logic
        if f_data_flag == 2:
            f_data = decrypt_hatch_data(f_data, f_crc, f_uncompressed_size)

        # Save data logic
        absolute_file_path: str = os.path.join(output_directory_path, f_filename.replace("/", "\\"))
        absolute_dir_path: str = os.path.dirname(absolute_file_path)

        if not os.path.exists(absolute_dir_path):
            try:
                os.makedirs(absolute_dir_path)
            except FileNotFoundError as error:
                logger.error(f"Can't create output directory! Exiting! Error: {error}")
                exit(1)

        output_file = open(absolute_file_path, "wb")
        output_file.write(f_data)
        output_file.close()

        hatch_file.seek(back_offset)

    hatch_file.close()
    logger.info("####### SUMMARY #######")
    known_percent: float = round((known_filenames_counter / file_count) * 100, 2)
    unknown_percent: float = round(((file_count - known_filenames_counter) / file_count) * 100, 2)
    logger.info(f"Known filenames: {known_filenames_counter} ({known_percent}%)")
    logger.info(f"Unknown filenames: {file_count - known_filenames_counter} ({unknown_percent}%)")
    logger.info(f"All filenames: {file_count}")
    logger.info("Ending export data...")
    return True


VERSION_NUM = "v1.1"
EXE_FILE_NAME = f"hatch_engine_archive_tool_{VERSION_NUM}.exe"
PROGRAM_NAME = f'Hatch Engine Archive Tool {VERSION_NUM}'


def main():
    """
    Main function of this program.
    """

    parser = argparse.ArgumentParser(prog=EXE_FILE_NAME,
                                     description=PROGRAM_NAME)
    parser.add_argument('-e', metavar='<hatch_file_path> <filenames_list_path> <output_directory>',
                        type=str, nargs=3, required=False, help='Extract data from HATCH archives')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    if args.e is not None:
        export_data(args.e[0], args.e[1], args.e[2])


if __name__ == "__main__":
    main()
