"""
Copyright © 2023  Bartłomiej Duda
License: GPL-3.0 License
"""

# Program tested on Python 3.11

# Ver    Date        Author               Comment
# v0.1   01.01.2023  Bartlomiej Duda      -


import argparse
import os
import sys
from typing import Optional
from reversebox.io_files.file_handler import FileHandler


class BytesHandler:
    def __init__(self, input_bytes: bytes):
        self.input_bytes = input_bytes

    def get_bytes(self, offset: int, size: int) -> bytes:
        output_bytes: bytes = self.input_bytes[offset:offset+size]
        return output_bytes


def decrypt_bytes(encrypted_data: bytes, key: int) -> bytes:
    decrypted_bytes: bytes = b''
    for i in range(len(encrypted_data)):
        raw_byte = encrypted_data[i]
        raw_byte = ((raw_byte - key) & 0xFF).to_bytes(byteorder="little", length=1)
        decrypted_bytes += raw_byte
    return decrypted_bytes


def export_data(pak_path: str) -> Optional[tuple]:
    """
    Function for exporting data
    """

    print("Starting PAK extract function...")

    # For debug only:
    # pak_path = "C:\\Users\\Lenovo\\Desktop\\PAK_RESEARCH\\launcher_dd.pak"
    # pak_path = "C:\\Users\\Lenovo\\Desktop\\PAK_RESEARCH\\pacman.pak"  - dont work
    # pak_path = "C:\\Users\\Lenovo\\Desktop\\PAK_RESEARCH\\launcher_pm.pak"
    # pak_path = "C:\\Users\\Lenovo\\Desktop\\PAK_RESEARCH\\digdug.pak"
    # pak_path = "C:\\Users\\Lenovo\\Desktop\\PAK_RESEARCH\\data.pak" - dont work

    pak_handler = FileHandler(pak_path, "rb")

    try:
        pak_handler.open()
    except FileNotFoundError:
        print("Error! Invalid file path: ", pak_path)
        exit(-1)

    # read header
    signature = pak_handler.read_str(6)
    if signature != "RWPACK":
        raise Exception("Wrong PAK file! Exiting!")

    pak_handler.seek(12)
    number_of_entries = pak_handler.read_uint32()
    encryption_flag = pak_handler.read_uint32()
    encryption_key = pak_handler.read_uint8()
    directory_size = number_of_entries * 60

    # read directory
    pak_handler.seek(36)
    directory: bytes = pak_handler.read_bytes(directory_size)
    directory_handler = BytesHandler(directory)

    # create main output path
    main_output_path = None
    if not main_output_path:
        main_output_path = pak_path + "_out"
        if not os.path.exists(main_output_path):
            try:
                os.makedirs(main_output_path)
            except FileNotFoundError:
                print("Can't create output directory! Exiting!")
                exit(1)

    # decrypt and parse directory
    for i in range(number_of_entries):
        entry_offset = i * 60

        filepath_bytes: bytes = directory_handler.get_bytes(entry_offset, 45)
        file_size_bytes: bytes = directory_handler.get_bytes(entry_offset + 48, 4)
        file_offset_bytes: bytes = directory_handler.get_bytes(entry_offset + 52, 4)
        unk4_bytes: bytes = directory_handler.get_bytes(entry_offset + 56, 4)

        if encryption_flag == 1:
            filepath_bytes: bytes = decrypt_bytes(filepath_bytes, encryption_key)
            file_size_bytes: bytes = decrypt_bytes(file_size_bytes, encryption_key)
            file_offset_bytes: bytes = decrypt_bytes(file_offset_bytes, encryption_key)
            unk4_bytes: bytes = decrypt_bytes(unk4_bytes, encryption_key)

        filepath_str = filepath_bytes.split(b'\x00')[0].decode("windows-1250")
        file_size_int = int.from_bytes(file_size_bytes, "little")
        file_offset_int = int.from_bytes(file_offset_bytes, "little")
        unk4_int = int.from_bytes(unk4_bytes, "little")

        pak_handler.seek(file_offset_int)
        file_data: bytes = pak_handler.read_bytes(file_size_int)

        if encryption_flag == 1:
            file_data: bytes = decrypt_bytes(file_data, encryption_key)

        absolute_file_path = os.path.join(main_output_path, *filepath_str.split("\\"))
        absolute_dir_path = os.path.dirname(absolute_file_path)
        if not os.path.exists(absolute_dir_path):
            try:
                os.makedirs(absolute_dir_path)
            except (FileNotFoundError, ValueError):
                print("Can't create output directory! Exiting!")
                exit(1)

        print(f"Writing {filepath_str}...")
        out_file = open(absolute_file_path, "wb")
        out_file.write(file_data)
        out_file.close()

    print(f"Data extracted successfully to {main_output_path}")
    return "OK", ""


VERSION_NUM = "v1.0"
EXE_FILE_NAME = f"namco_all_stars_pak_extractor_{VERSION_NUM}.exe"
PROGRAM_NAME = f'Namco All-Stars PAK Extractor {VERSION_NUM}'


def main():
    """
    Main function of this program.
    """
    parser = argparse.ArgumentParser(prog=EXE_FILE_NAME,
                                     description=PROGRAM_NAME)
    # fmt: off
    parser.add_argument('-e', '--ext', metavar='<pak_file_path>',
                        type=str, nargs=1, required=False, help='Extract data from Namco All-Stars PAK archives')
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

    sys.exit(0)


if __name__ == "__main__":
    main()
