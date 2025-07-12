"""
Copyright © 2025  Bartłomiej Duda
License: GPL-3.0 License
"""
import os
import sys
import argparse

from PIL import Image
from reversebox.common.logger import get_logger
from reversebox.image.image_decoder import ImageDecoder
from reversebox.image.image_formats import ImageFormats
from reversebox.image.pillow_wrapper import PillowWrapper
from reversebox.image.swizzling.swizzle_gamecube import unswizzle_gamecube
from reversebox.io_files.file_handler import FileHandler

logger = get_logger(__name__)


def parse_txfl(input_txfl_file_path: str, output_file_path: str) -> None:
    image_decoder = ImageDecoder()
    wrapper = PillowWrapper()
    txfl_file = FileHandler(input_txfl_file_path, "rb", "big")

    file_version = txfl_file.read_uint32()
    file_signature = txfl_file.read_bytes(4)

    if file_version != 9:
        raise Exception("Not supported TXFL version!")

    if file_signature != b'TXFL':
        raise Exception("Not supported TXFL file!")

    unknown1 = txfl_file.read_int32()
    if unknown1 != -1:
        raise Exception("Unexpected unknown value")

    texture_name_length = txfl_file.read_uint32()
    texture_name = txfl_file.read_str(texture_name_length-1, "utf8")
    txfl_file.read_uint8()  # null terminator

    txfl_file.read_uint32()  # data size
    txfl_file.read_bytes(16)  # unknown
    image_width = txfl_file.read_uint16()
    image_height = txfl_file.read_uint16() // 2
    txfl_file.read_bytes(12)  # unknown
    image_size = image_width * image_height
    image_data = txfl_file.read_bytes(image_size)

    image_data = unswizzle_gamecube(image_data, image_width, image_height, bpp=8)

    decoded_image_data: bytes = image_decoder.decode_image(
            image_data, image_width, image_height, ImageFormats.GRAY8, "little"
        )

    pillow_image: Image = wrapper.get_pillow_image_from_rgba8888_data(decoded_image_data, image_width, image_height)
    pillow_image.save(output_file_path)
    logger.info(f"Texture {texture_name} processed successfully.")
    return


def process_all_txfl_files(input_folder: str, output_folder: str) -> None:
    for root, _, files in os.walk(input_folder):
        for filename in files:
            input_file_path = os.path.join(root, filename)
            output_file_path = os.path.join(output_folder, filename + "_out.png")
            if os.path.isfile(input_file_path):
                parse_txfl(input_file_path, output_file_path)


def main() -> None:
    """
    Main function of this program.
    """
    logger.info("Starting main...")

    parser = argparse.ArgumentParser(description="Parse TXFL files")
    parser.add_argument("input_folder", help="Input folder path")
    parser.add_argument("output_folder", help="Output folder path")

    args = parser.parse_args()

    if not os.path.isdir(args.input_folder):
        logger.info(f"Input folder '{args.input_folder}' doesn't exist.")
        return

    os.makedirs(args.output_folder, exist_ok=True)
    process_all_txfl_files(args.input_folder, args.output_folder)

    logger.info("End of main... Program has been executed successfully!")
    sys.exit(0)


if __name__ == "__main__":
    main()
