"""
Copyright © 2025  Bartłomiej Duda
License: GPL-3.0 License
"""

import argparse
import os
import sys

from reversebox.common.logger import get_logger
from reversebox.image.image_decoder import ImageDecoder
from reversebox.image.image_formats import ImageFormats
from reversebox.image.pillow_wrapper import PillowWrapper
from reversebox.io_files.file_handler import FileHandler

logger = get_logger(__name__)


def export_data(rfh_file_path: str, rfd_file_path: str, output_directory_path: str) -> None:
    """
    Function for exporting data
    """
    logger.info(f"Starting export data from \"{os.path.basename(rfh_file_path)}\" file...")

    rfh_file = FileHandler(rfh_file_path, "rb")
    # TODO

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
    group.add_argument("-e", "--export", nargs=2, metavar=("rfh_file_path", "output_directory"), help="Export from RFH/RFD file")
    group.add_argument("-i", "--import", nargs=2, metavar=("input_directory", "rfh_file_path"), help="Import to RFH/RFD file")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    logger.info(f"Running {PROGRAM_NAME}...")

    if getattr(args, "export"):
        rfh_path, output_path = getattr(args, "export")
        rfd_path: str = rfh_path.replace("rfh", "rfd")

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
