"""
Copyright © 2025  Bartłomiej Duda
License: GPL-3.0 License
"""

import os
import zlib
from dataclasses import dataclass
from typing import Optional

from reversebox.common.logger import get_logger
from reversebox.crc.crc32_iso_hdlc import CRC32Handler
from reversebox.io_files.file_handler import FileHandler


logger = get_logger(__name__)


# # Index entry from hatch archive
# @dataclass
# class IndexEntry:
#     crc32: int
#     file_offset: int
#     file_uncompressed_size: int
#     data_flag: int
#     file_compressed_size: int
#     file_name: Optional[str] = None


# Entry for filename from TXT file and for calculated CRC value
@dataclass
class KnownCRCEntry:
    crc32: int
    file_name: str


def export_data(hatch_file_path: str, filenames_list_file_path: str) -> bool:
    """
    Function for exporting data
    """
    logger.info("Starting export data...")

    # Reading names from TXT file
    filenames_file = open(filenames_list_file_path, "rt")
    # index_entries_list: list[IndexEntry] = []
    known_crc_entries_list: list[KnownCRCEntry] = []
    crc_handler = CRC32Handler()

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

        logger.info(f'{i}) {f_filename}')

        hatch_file.seek(f_offset)

        if f_compressed_size != f_uncompressed_size:
            f_data: bytes = hatch_file.read_bytes(f_compressed_size)
            f_data = zlib.decompress(f_data)
        else:
            f_data: bytes = hatch_file.read_bytes(f_uncompressed_size)


        # TODO

        hatch_file.seek(back_offset)

        # index_entry: IndexEntry = IndexEntry(
        #     crc32=f_crc,
        #     file_offset=f_offset,
        #     file_uncompressed_size=f_uncompressed_size,
        #     data_flag=f_data_flag,
        #     file_compressed_size=f_compressed_size,
        #     file_name=f_filename
        # )
        # index_entries_list.append(index_entry)

    hatch_file.close()
    logger.info("Ending export data...")
    return True


def main():
    """
    Main function of this program.
    """
    hatch_file_path = os.environ['HATCH_FILE_PATH']
    filenames_list_file_path = os.environ['FILENAMES_LIST_FILE_PATH']
    export_data(hatch_file_path, filenames_list_file_path)


if __name__ == "__main__":
    main()
