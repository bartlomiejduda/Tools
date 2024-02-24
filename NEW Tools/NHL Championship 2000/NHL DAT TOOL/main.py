"""
Copyright © 2024  Bartłomiej Duda
License: GPL-3.0 License
"""

# Program tested on Python 3.11

# Ver    Date        Author               Comment
# v1.0   24.02.2024  Bartlomiej Duda      -


import argparse
import sys
from typing import Optional
from reversebox.io_files.file_handler import FileHandler
from reversebox.common.logger import get_logger
from reversebox.encryption.encryption_xor_basic import xor_cipher_basic

logger = get_logger("main")


VERSION_NUM = "v1.0"
EXE_FILE_NAME = f"nhl_dat_tool_{VERSION_NUM}.exe"
PROGRAM_NAME = f'NHL DAT Tool {VERSION_NUM}'


def process_data(input_dat_path: str, output_dat_path) -> Optional[tuple]:
    """
    Function for decrypting and encrypting data (XOR Cipher)
    """
    logger.info("Initializing process_data...")
    input_file_handler = FileHandler(input_dat_path, "rb")
    output_file_handler = FileHandler(output_dat_path, "wb")
    input_file_handler.open()
    output_file_handler.open()

    for i in range(input_file_handler.get_file_size()):
        read_byte = input_file_handler.read_bytes(1)
        if read_byte not in (b'\x0D', b'\x0A'):
            output_file_handler.write_bytes(xor_cipher_basic(read_byte, b'\xFF'))
        else:
            output_file_handler.write_bytes(read_byte)

    input_file_handler.close()
    input_file_handler.close()
    logger.info("process_data finished OK")
    return "OK", ""


def main():
    """
    Main function of this program.
    """
    parser = argparse.ArgumentParser(prog=EXE_FILE_NAME,
                                     description=PROGRAM_NAME)
    # fmt: off
    parser.add_argument('-p', '--process', metavar='<dat_file_path> <out_dat_path>',
                        type=str, nargs=2, required=False, help='Decrypt/Encrypt DAT file (XOR Cipher)')
    # fmt: on

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    if args.process is not None:
        code, status = process_data(args.process[0], args.process[1])
        if code != "OK":
            logger.info(f"{code}: {status}")
            sys.exit(-1)

    logger.info("End of main... Program has been executed successfully!")
    sys.exit(0)


if __name__ == "__main__":
    main()
