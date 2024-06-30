"""
Copyright © 2024  Bartłomiej Duda
License: GPL-3.0 License
"""
import argparse
import os
import sys

from reversebox.common.logger import get_logger
from reversebox.crc.crc32_iso_hdlc import CRC32Handler
from reversebox.io_files.file_handler import FileHandler
from dataclasses import dataclass

logger = get_logger(__name__)

crc32_handler = CRC32Handler()


@dataclass
class FilenameEntry:
    filename: str
    crc32: int


def load_filenames() -> list:
    filenames_list = []
    current_directory = os.path.dirname(os.path.realpath(__file__))
    filelist_directory = os.path.join(current_directory, "filenames")

    for file in os.listdir(filelist_directory):
        if file.endswith(".txt"):
            with open(os.path.join(filelist_directory, file), "rt") as filelist_file:
                for line in filelist_file:
                    out_line: str = line.rstrip("\n")
                    calculated_crc32: int = crc32_handler.calculate_crc32(out_line.encode("utf8"))

                    f_name_entry: FilenameEntry = FilenameEntry(
                        filename=out_line,
                        crc32=calculated_crc32
                    )

                    filenames_list.append(f_name_entry)

    return filenames_list


def extract_data(tre_file_path: str, output_directory: str, endianess: str = "little") -> bool:
    logger.info("Extracting data. Please wait...")
    filenames: list = load_filenames()

    if not os.path.exists(output_directory):
        os.makedirs(output_directory)

    tre_file = FileHandler(tre_file_path, "rb", endianess_str=endianess)
    tre_file.open()
    number_of_files: int = tre_file.read_uint32()
    known_filenames: int = 0

    for i in range(number_of_files):
        file_offset: int = tre_file.read_uint32()
        file_size: int = tre_file.read_uint32()
        name_crc: int = tre_file.read_uint32()
        data_crc: int = tre_file.read_uint32()
        back_offset: int = tre_file.get_position()
        output_filename: str = f"file_{i}.bin"

        for filename_entry in filenames:
            if filename_entry.crc32 == name_crc:
                output_filename = filename_entry.filename
                known_filenames += 1
                break

        tre_file.seek(file_offset)
        file_data: bytes = tre_file.read_bytes(file_size)
        tre_file.seek(back_offset)
        output_filename = os.path.join(output_directory, output_filename)
        if not os.path.exists(os.path.dirname(output_filename)):
            os.makedirs(os.path.dirname(output_filename))

        with open(output_filename, "wb") as output_file:
            output_file.write(file_data)

    tre_file.close()
    logger.info(f"Total files: {number_of_files}, Known_filenames: {known_filenames}, Unknown_filenames: {number_of_files-known_filenames}")
    logger.info(f"All files have been extracted to {output_directory}")
    return True


VERSION_NUM = "v1.0"
EXE_FILE_NAME = f"acclaim_tre_tool_{VERSION_NUM}.exe"
PROGRAM_NAME = f'Acclaim TRE Tool {VERSION_NUM}'

if __name__ == '__main__':
    """
    Main function of this program.
    """
    logger.info("Start main")
    parser = argparse.ArgumentParser(prog=EXE_FILE_NAME,
                                     description=PROGRAM_NAME)
    # fmt: off
    parser.add_argument('-e', '--ext', metavar='<tre_file_path>',
                        type=str, nargs=1, required=True, help='Extract data from TRE archives')
    parser.add_argument('-o', '--out', metavar='<output_path>',
                        type=str, nargs=1, required=True, help='Output Directory')
    parser.add_argument('-b', '--big',
                        type=str, required=False, help='Set Endianess to BIG')
    # fmt: on

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    if args.ext is not None:
        if args.big:
            endianess="big"
        else:
            endianess="little"

        logger.info(f"Endianess: {endianess}")
        logger.info(f"TRE file path: {args.ext[0]}")
        logger.info(f"OUT file path: {args.out[0]}")
        result = extract_data(args.ext[0], args.out[0], endianess=endianess)
        if not result:
            logger.error("Error while extracting data!")
            sys.exit(-1)

    logger.info("End main")
    sys.exit(0)
