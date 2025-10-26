"""
Copyright © 2025  Bartłomiej Duda
License: GPL-3.0 License
"""

import argparse
import os
import sys

from reversebox.common.logger import get_logger
from reversebox.compression.compression_huffman_intelligent import huffman_decompress_data
from reversebox.compression.compression_rle_tzar import decompress_rle_tzar
from reversebox.compression.compression_zlib import ZLIBHandler
from reversebox.image.image_decoder import ImageDecoder
from reversebox.image.image_formats import ImageFormats
from reversebox.image.pillow_wrapper import PillowWrapper
from reversebox.io_files.file_handler import FileHandler

logger = get_logger(__name__)


def convert_rle_images_to_dds(rle_input_directory_path: str, dds_output_directory_path: str) -> None:
    """
    Function for converting RLE to DDS
    """

    for rle_file in os.listdir(rle_input_directory_path):
        rle_file_path = os.path.join(rle_input_directory_path, rle_file)
        if os.path.isfile(rle_file_path):

            logger.info(f"Starting convert_rle_image_to_dds for \"{os.path.basename(rle_file_path)}\" file...")

            rle_file = FileHandler(rle_file_path, "rb")
            signature = rle_file.read_bytes(4)
            if signature != b' elr':
                raise Exception("Not supported TZAR RLE file!")
            unknown1: int = rle_file.read_uint32()
            unknown2: int = rle_file.read_uint32()
            unknown3: int = rle_file.read_uint32()
            signature2 = rle_file.read_bytes(4)
            if signature2 != b'RLE\x00':
                raise Exception("Not supported TZAR RLE file!")
            image_width: int = rle_file.read_uint16()
            image_height: int = rle_file.read_uint16()
            file_type: int = rle_file.read_uint16()
            compressed_file_size: int = rle_file.read_uint32()
            number_of_palette_entries: int = rle_file.read_uint32()
            unknown5: int = rle_file.read_uint32()

            if image_height > 300:
                continue  # TODO - temp

            palette_data: bytes = b''
            if number_of_palette_entries > 0:
                palette_data: bytes = rle_file.read_bytes(4 * number_of_palette_entries)

            # decompressing and decoding logic
            if file_type == 1:
                image_bpp: int = 8
            elif file_type in (3, 7):
                image_bpp: int = 16
            else:
                raise Exception(f"Not supported file type: {file_type}")

            compressed_image_data: bytes = rle_file.read_bytes(compressed_file_size)
            raw_image_data: bytes = decompress_rle_tzar(compressed_image_data, image_width, image_height, image_bpp)
            image_decoder = ImageDecoder()
            wrapper = PillowWrapper()

            if file_type == 1:
                decoded_image_data: bytes = image_decoder.decode_indexed_image(raw_image_data, palette_data, image_width, image_height,
                                                                               ImageFormats.PAL8_TZAR, ImageFormats.BGRA8888_TZAR)
            elif file_type == 3 or file_type == 7:
                decoded_image_data: bytes = image_decoder.decode_image(raw_image_data, image_width, image_height,
                                                                       ImageFormats.BGRA5551_TZAR)
            else:
                raise Exception(f"Not supported file type: {file_type}")

            pil_image = wrapper.get_pillow_image_from_rgba8888_data(decoded_image_data, image_width, image_height)

            dds_file_name: str = os.path.basename(rle_file_path).replace("RLE", "DDS").replace("rle", "dds")
            dds_output_path: str = os.path.join(dds_output_directory_path, dds_file_name)
            pil_image.save(dds_output_path)

            logger.info(f"Image file \"{os.path.basename(rle_file_path)}\" converted successfully...")

    return


VERSION_NUM = "v1.0"
EXE_FILE_NAME = f"tzar_rle_tool_{VERSION_NUM}.exe"
PROGRAM_NAME = f'Tzar RLE Tool {VERSION_NUM}'


def main():
    """
    Main function of this program.
    """

    parser = argparse.ArgumentParser(prog=EXE_FILE_NAME, description=PROGRAM_NAME)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-e", "--export", nargs=2, metavar=("rle_directory_path", "dds_directory_path"), help="Covert from RLE to DDS")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    logger.info(f"Running {PROGRAM_NAME}...")

    if getattr(args, "export"):
        rle_directory_path, dds_directory_path = getattr(args, "export")
        convert_rle_images_to_dds(rle_directory_path, dds_directory_path)

    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
