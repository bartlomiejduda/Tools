"""
Copyright © 2024  Bartłomiej Duda
License: GPL-3.0 License
"""
import struct
import sys

from reversebox.common.logger import get_logger
from reversebox.image.image_decoder import ImageDecoder
from reversebox.image.image_formats import ImageFormats
from reversebox.image.pillow_wrapper import PillowWrapper

from face1 import face1_data
from face3 import face3_data

logger = get_logger(__name__)


def get_image(tex_data: list, file_name: str, image_width: int, image_height: int, image_format: ImageFormats) -> bool:
    logger.info(f"Get image start, file_name={file_name}")
    number_of_bytes: int = len(tex_data) * 2
    data_array: bytearray = bytearray(number_of_bytes)
    image_decoder = ImageDecoder()
    wrapper = PillowWrapper()

    bytes_counter: int = 0
    for i in range(len(tex_data)):
        pixel_data: bytes = struct.pack("<H", tex_data[i])
        data_array[bytes_counter] = pixel_data[0]
        data_array[bytes_counter+1] = pixel_data[1]
        bytes_counter += 2

    decoded_image_data: bytes = image_decoder.decode_image(
        data_array, image_width, image_height, image_format
    )
    pil_image = wrapper.get_pillow_image_from_rgba8888_data(decoded_image_data, image_width, image_height)
    pil_image.save(file_name + ".png")

    logger.info("Get image end")
    return True


def main():
    """
    Main function of this program.
    """
    logger.info("Starting main...")

    get_image(face1_data, "face1", 128, 128, ImageFormats.RGB565)
    get_image(face3_data, "face3", 128, 128, ImageFormats.RGB565)

    logger.info("End of main... Program has been executed successfully!")
    sys.exit(0)


if __name__ == "__main__":
    main()
