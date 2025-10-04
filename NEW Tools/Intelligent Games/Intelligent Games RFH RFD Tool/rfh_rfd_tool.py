"""
Copyright © 2025  Bartłomiej Duda
License: GPL-3.0 License
"""

import argparse
import os
import sys

from reversebox.common.logger import get_logger
from reversebox.compression.compression_huffman_intelligent import huffman_decompress_data
from reversebox.io_files.file_handler import FileHandler

logger = get_logger(__name__)


def export_data(rfh_file_path: str, rfd_file_path: str, output_directory_path: str) -> None:
    """
    Function for exporting data
    """
    logger.info(f"Starting export data from \"{os.path.basename(rfh_file_path)}\" file...")

    rfh_file = FileHandler(rfh_file_path, "rb")
    rfd_file = FileHandler(rfd_file_path, "rb")
    rfh_total_size: int = rfh_file.get_file_size()

    while 1:
        filename_length: int = rfh_file.read_uint32()
        filename: str = rfh_file.read_bytes(filename_length).decode("utf8").rstrip("\x00")
        file_size = rfh_file.read_uint32()
        compression_flag: int = rfh_file.read_uint32()
        file_data: bytes = rfd_file.read_bytes(file_size)
        file_path: str = os.path.join(output_directory_path, filename)
        os.makedirs(os.path.dirname(file_path), exist_ok=True)

        if compression_flag == 1:
            file_data = huffman_decompress_data(file_data)

        logger.info(f"Saving {filename}...")
        out_file = open(file_path, "wb")
        out_file.write(file_data)
        out_file.close()

        current_offset: int = rfh_file.get_position()
        if current_offset >= rfh_total_size:
            break

    logger.info(f"Data from file \"{os.path.basename(rfh_file_path)}\" exported successfully...")
    return


VERSION_NUM = "v1.0"
EXE_FILE_NAME = f"rfh_rfd_tool_{VERSION_NUM}.exe"
PROGRAM_NAME = f'Intelligent Games RFH/RFD Tool {VERSION_NUM}'


def main():
    """
    Main function of this program.
    """

    parser = argparse.ArgumentParser(prog=EXE_FILE_NAME, description=PROGRAM_NAME)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-e", "--export", nargs=3, metavar=("rfh_file_path", "rfd_file_path", "output_directory"), help="Export from RFH/RFD file")
    # group.add_argument("-i", "--import", nargs=2, metavar=("input_directory", "rfh_file_path", "rfd_file_path"), help="Import to RFH/RFD file")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    logger.info(f"Running {PROGRAM_NAME}...")

    if getattr(args, "export"):
        rfh_path, rfd_path, output_path = getattr(args, "export")

        if not os.path.isfile(rfh_path):
            logger.error(f"[ERROR] File does not exist: {rfh_path}")
            sys.exit(1)
        if not os.path.isfile(rfd_path):
            logger.error(f"[ERROR] File does not exist: {rfd_path}")
            sys.exit(1)
        if not os.path.isdir(output_path):
            logger.error(f"[ERROR] Directory does not exist: {output_path}")
            sys.exit(1)
        export_data(rfh_path, rfd_path, output_path)

    elif getattr(args, "import"):
        input_path, rfh_path = getattr(args, "import")
        if not os.path.isdir(input_path):
            logger.error(f"[ERROR] Directory does not exist: {input_path}")
            sys.exit(1)
        # TODO - import

    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
