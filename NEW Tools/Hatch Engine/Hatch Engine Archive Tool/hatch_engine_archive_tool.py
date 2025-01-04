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
from reversebox.io_files.bytes_helper_functions import set_uint32
from reversebox.io_files.file_handler import FileHandler


logger = get_logger(__name__)

crc_handler = CRC32Handler()


# Entry for filename from TXT file and for calculated CRC value
@dataclass
class KnownCRCEntry:
    crc32: int
    file_name: str


def decrypt_hatch_data(f_data: bytes, filename: str, f_size: int) -> bytes:
    keyA: bytearray = bytearray(16)
    keyB: bytearray = bytearray(16)
    decrypted_data: bytearray = bytearray(f_data)

    filename_hash: int = crc_handler.calculate_crc32(filename.encode("ascii"))
    encoded_filename_hash: bytes = set_uint32(filename_hash, "<")
    size_hash: int = crc_handler.calculate_crc32(f_data)
    encoded_size_hash: bytes = set_uint32(size_hash, "<")

    keyA[0:4] = encoded_filename_hash
    keyA[4:8] = encoded_filename_hash
    keyA[8:12] = encoded_filename_hash
    keyA[12:16] = encoded_filename_hash

    keyB[0:4] = encoded_size_hash
    keyB[4:8] = encoded_size_hash
    keyB[8:12] = encoded_size_hash
    keyB[12:16] = encoded_size_hash

    swap_nibbles: int = 0
    index_keyA: int = 0
    index_keyB: int = 8

    xor_value = (f_size >> 2) & 0x7F

    for x in range(f_size):
        temp = decrypted_data[x]

        temp ^= xor_value ^ keyB[index_keyB]
        index_keyB += 1

        if swap_nibbles:
            temp = ((temp & 0x0F) << 4) | ((temp & 0xF0) >> 4)

        temp ^= keyA[index_keyA]
        index_keyA += 1

        decrypted_data[x] = temp

        if index_keyA <= 15:
            if index_keyB > 12:
                index_keyB = 0
                swap_nibbles ^= 1
        elif index_keyB <= 8:
            index_keyA = 0
            swap_nibbles ^= 1
        else:
            xor_value = (xor_value + 2) & 0x7F
            if swap_nibbles:
                swap_nibbles = False
                index_keyA = xor_value % 7
                index_keyB = (xor_value % 12) + 2
            else:
                swap_nibbles = True
                index_keyA = (xor_value % 12) + 3
                index_keyB = xor_value % 7

    return f_data


def export_data(hatch_file_path: str, filenames_list_file_path: str, output_directory_path: str) -> bool:
    """
    Function for exporting data
    """
    logger.info("Starting export data...")

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
        f_filename_known_flag: bool = False
        back_offset: int = hatch_file.get_position()

        for known_crc_entry in known_crc_entries_list:
            if known_crc_entry.crc32 == f_crc:
                f_filename = known_crc_entry.file_name
                f_filename_known_flag = True

        logger.info(f'{i}) {f_filename}')

        hatch_file.seek(f_offset)

        # Decompression logic
        if f_compressed_size != f_uncompressed_size:
            f_data: bytes = hatch_file.read_bytes(f_compressed_size)
            f_data = zlib.decompress(f_data)
        else:
            f_data: bytes = hatch_file.read_bytes(f_uncompressed_size)

        # Decryption logic
        if f_data_flag == 2 and f_filename_known_flag:
            f_data = decrypt_hatch_data(f_data, f_filename, f_uncompressed_size)
            pass

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
    logger.info("Ending export data...")
    return True


def main():
    """
    Main function of this program.
    """
    hatch_file_path: str = os.environ['HATCH_FILE_PATH']
    filenames_list_file_path: str = os.environ['FILENAMES_LIST_FILE_PATH']
    output_directory_path: str = os.environ['OUTPUT_DIRECTORY_PATH']
    export_data(hatch_file_path, filenames_list_file_path, output_directory_path)


if __name__ == "__main__":
    main()
