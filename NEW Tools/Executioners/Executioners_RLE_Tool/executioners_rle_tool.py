"""
Copyright © 2025  Bartłomiej Duda
License: GPL-3.0 License
"""

import os
from reversebox.common.logger import get_logger
from reversebox.io_files.file_handler import FileHandler


logger = get_logger(__name__)


def decompress_rle_executioners(image_data: bytes, img_width: int, img_height: int) -> bytes:
    pass  # TODO


def convert_image_file(image_file_path: str, palette_file_path: str) -> bool:
    """
    Function for converting Executioners images
    """
    logger.info("Starting convert image...")

    palette_file = open(palette_file_path, "rb")
    palette_data: bytes = palette_file.read()
    palette_file.close()

    image_file = FileHandler(image_file_path, "rb")
    signature: int = image_file.read_uint8()

    if signature != 16:
        raise Exception("Invalid Executioners RLE file!")

    img_width: int = image_file.read_uint8()
    img_height: int = image_file.read_uint8()
    header_end_marker: int = image_file.read_uint8()

    if header_end_marker != 255:
        raise Exception("Invalid header end marker!")

    file_size: int = image_file.get_file_size()
    image_size: int = file_size - 4
    image_data: bytes = image_file.read_bytes(image_size)

    image_data: bytes = decompress_rle_executioners(image_data, img_width, img_height)

    logger.info("Ending convert image...")
    return True


def main():
    """
    Main function of this program.
    """
    image_file_path: str = os.environ['IMAGE_FILE_PATH']
    palette_file_path: str = os.environ['PALETTE_FILE_PATH']
    convert_image_file(image_file_path, palette_file_path)


if __name__ == "__main__":
    main()
