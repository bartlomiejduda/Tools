"""
Copyright © 2025  Bartłomiej Duda
License: GPL-3.0 License
"""

import argparse
import sys
from PIL import Image
from reversebox.common.logger import get_logger
from reversebox.image.compression.compression_rle_executioners import decompress_rle_executioners
from reversebox.image.image_decoder import ImageDecoder
from reversebox.image.image_formats import ImageFormats
from reversebox.image.pillow_wrapper import PillowWrapper
from reversebox.io_files.file_handler import FileHandler


logger = get_logger(__name__)


def convert_image_file(image_file_path: str, palette_file_path: str, output_image_path: str) -> bool:
    """
    Function for converting Executioners images
    """
    logger.info("Starting convert image...")

    image_decoder = ImageDecoder()
    wrapper = PillowWrapper()

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

    image_data: bytes = decompress_rle_executioners(image_data, img_width, img_height, 8)
    image_data = image_decoder.decode_indexed_image(image_data, palette_data, img_width, img_height, ImageFormats.PAL8_RGB888)
    pil_image: Image = wrapper.get_pillow_image_from_rgba8888_data(image_data, img_width, img_height)
    pil_image.save(output_image_path)

    logger.info(f"Image saved to {output_image_path}")
    logger.info("Ending convert image...")
    return True


VERSION_NUM = "v1.0"
EXE_FILE_NAME = f"executioners_rle_tool_{VERSION_NUM}.exe"
PROGRAM_NAME = f'Executioners RLE Tool {VERSION_NUM}'


def main():
    """
    Main function of this program.
    """

    parser = argparse.ArgumentParser(prog=EXE_FILE_NAME,
                                     description=PROGRAM_NAME)
    parser.add_argument('-e', metavar='<image_file_path> <palette_file_path> <output_image_file_path>',
                        type=str, nargs=3, required=False, help='Extract images from VOL files')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    if args.e is not None:
        convert_image_file(args.e[0], args.e[1], args.e[2])


if __name__ == "__main__":
    main()
