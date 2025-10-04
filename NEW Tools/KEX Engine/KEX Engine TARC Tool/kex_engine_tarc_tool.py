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


def export_data(tarc_file_path: str, output_directory_path: str) -> None:
    """
    Function for exporting data
    """
    logger.info(f"Starting export data from \"{os.path.basename(tarc_file_path)}\" file...")

    tarc_file = FileHandler(tarc_file_path, "rb")
    total_file_size: int = tarc_file.get_file_size()
    if total_file_size < 4:
        raise Exception("TARC file is too small!")

    chunk_signature: bytes = tarc_file.read_bytes(4)

    if chunk_signature != b'TARC':
        raise Exception("Invalid KEX Engine TARC file signature!")

    archive_version: int = tarc_file.read_uint32()
    if archive_version != 1:
        raise Exception(f"Version {archive_version} not supported!")

    number_of_entries: int = tarc_file.read_uint32()
    base_offset: int = tarc_file.read_uint64()

    for i in range(number_of_entries):
        filename: str = tarc_file.read_bytes(64).decode("utf8").rstrip("\x00")
        file_offset: int = tarc_file.read_int64()
        file_offset += base_offset
        file_size: int = tarc_file.read_int32()
        image_width: int = tarc_file.read_int16()
        image_height: int = tarc_file.read_int16()
        tarc_file.read_int16()  # number of mipmaps
        pixel_format: int = tarc_file.read_int16()
        back_offset: int = tarc_file.get_position()

        logger.info(f"Extracting {filename}...")
        tarc_file.seek(file_offset)
        image_data: bytes = tarc_file.read_bytes(file_size)
        tarc_file.seek(back_offset)

        if pixel_format == 1:
            image_format = ImageFormats.RGBA8888
        elif pixel_format == 14:
            image_format = ImageFormats.BC1_DXT1
        elif pixel_format == 16:
            image_format = ImageFormats.BC3_DXT5
        elif pixel_format == 33:
            image_format = ImageFormats.BC7_UNORM
        else:
            logger.warning(f"Unsupported pixel format: {pixel_format}!")
            image_format = None

        if image_format:
            filename += ".png"
            file_path: str = os.path.join(output_directory_path, filename)
            if pixel_format == 1:
                image_data = ImageDecoder().decode_image(image_data, image_width, image_height, image_format)
            else:
                image_data = ImageDecoder().decode_compressed_image(image_data, image_width, image_height, image_format)
            pil_image = PillowWrapper().get_pillow_image_from_rgba8888_data(image_data, image_width, image_height)
            pil_image.save(file_path)
        else:
            filename = "UNKNOWN_" + filename + f"_format_{pixel_format}_{image_width}x{image_height}" + ".bin"
            file_path: str = os.path.join(output_directory_path, filename)
            output_file = open(file_path, "wb")
            output_file.write(image_data)
            output_file.close()

    logger.info(f"Data from file \"{os.path.basename(tarc_file_path)}\" exported successfully...")
    return


VERSION_NUM = "v1.0"
EXE_FILE_NAME = f"kex_engine_tarc_tool_{VERSION_NUM}.exe"
PROGRAM_NAME = f'KEX Engine TARC Tool {VERSION_NUM}'


def main():
    """
    Main function of this program.
    """

    parser = argparse.ArgumentParser(prog=EXE_FILE_NAME, description=PROGRAM_NAME)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-e", "--export", nargs=2, metavar=("tarc_file_path", "output_directory"), help="Export from TARC file")
    # group.add_argument("-i", "--import", nargs=2, metavar=("input_directory", "tarc_file_path"), help="Import to TARC file")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    logger.info(f"Running {PROGRAM_NAME}...")

    if getattr(args, "export"):
        tarc_path, output_path = getattr(args, "export")

        if not os.path.isfile(tarc_path):
            logger.error(f"[ERROR] File does not exist: {tarc_path}")
            sys.exit(1)
        if not os.path.isdir(output_path):
            logger.error(f"[ERROR] Directory does not exist: {output_path}")
            sys.exit(1)
        export_data(tarc_path, output_path)

    elif getattr(args, "import"):
        input_path, tarc_path = getattr(args, "import")
        if not os.path.isdir(input_path):
            logger.error(f"[ERROR] Directory does not exist: {input_path}")
            sys.exit(1)
        # TODO - import

    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
