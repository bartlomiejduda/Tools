"""
Copyright © 2024  Bartłomiej Duda
License: GPL-3.0 License
"""

# Ver    Date        Author               Comment
# v1.0   25.07.2024  Bartlomiej Duda      -
# v1.1   26.07.2024  Bartlomiej Duda      Added support for more TEX images


import struct
import sys

from reversebox.common.logger import get_logger
from reversebox.compression.compression_mio0 import Mio0Handler
from reversebox.image.image_decoder import ImageDecoder
from reversebox.image.image_formats import ImageFormats
from reversebox.image.pillow_wrapper import PillowWrapper

from data.face1 import face1_data
from data.face3 import face3_data
from data.ko_msel_bg import ko_msel_bg_data
from data.ko_title_TIS import ko_title_TIS_data
from data.ko_title_TIS2 import ko_title_TIS2_data
from data.sot_falcon32 import sot_falcon32_data

logger = get_logger(__name__)


def convert_to_data_array(tex_data: list, value_size: int) -> bytearray:
    number_of_bytes: int = len(tex_data) * 2
    data_array: bytearray = bytearray(number_of_bytes)
    bytes_counter: int = 0
    for i in range(len(tex_data)):
        if value_size == 8:
            pixel_data: bytes = struct.pack("B", tex_data[i])
            data_array[bytes_counter] = pixel_data[0]
            bytes_counter += 1
        elif value_size == 16:
            pixel_data: bytes = struct.pack("<H", tex_data[i])
            data_array[bytes_counter] = pixel_data[0]
            data_array[bytes_counter + 1] = pixel_data[1]
            bytes_counter += 2
        else:
            raise Exception("Unsupported bpp value!")
    return data_array


def save_data_for_testing(tex_data: list, file_name: str, value_size: int) -> bool:
    logger.info("Saving data for testing")
    compression_handler = Mio0Handler()
    converted_data: bytearray = convert_to_data_array(tex_data, value_size)
    decompressed_data: bytes = compression_handler.decompress_data(converted_data, "big")
    file_name = file_name + ".bin"
    with open(file_name, 'wb') as f:
        f.write(decompressed_data)
    logger.info(f"Data saved as {file_name}")
    return True


def get_image(tex_data: list, file_name: str, image_width: int, image_height: int, image_format: ImageFormats, value_size: int, is_compressed: bool = False) -> bool:
    logger.info(f"Get image start, file_name={file_name}")

    image_decoder = ImageDecoder()
    wrapper = PillowWrapper()
    compression_handler = Mio0Handler()
    converted_data: bytearray = convert_to_data_array(tex_data, value_size)

    if is_compressed:
        converted_data = bytearray(compression_handler.decompress_data(bytes(converted_data), "big"))

    decoded_image_data: bytes = image_decoder.decode_image(
        converted_data, image_width, image_height, image_format
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

    get_image(face1_data, "data\\face1", 128, 128, ImageFormats.RGB565, 16)
    get_image(face3_data, "data\\face3", 128, 128, ImageFormats.RGB565, 16)
    get_image(sot_falcon32_data, "data\\sot_falcon32", 32, 32, ImageFormats.RGBX5551, 16)
    get_image(ko_msel_bg_data, "data\\ko_msel_bg", 320, 240, ImageFormats.RGBX4444, 16)

    # save_data_for_testing(ko_title_TIS_data, "data\\ko_title_TIS", 8)
    # save_data_for_testing(ko_title_TIS2_data, "data\\ko_title_TIS2", 8)
    get_image(ko_title_TIS_data, "data\\ko_title_TIS", 304, 240, ImageFormats.RGBX4444, 8, True)
    get_image(ko_title_TIS2_data, "data\\ko_title_TIS2", 320, 240, ImageFormats.RGBX4444, 8, True)


    logger.info("End of main... Program has been executed successfully!")
    sys.exit(0)


if __name__ == "__main__":
    main()
