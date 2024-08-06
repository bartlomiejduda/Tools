"""
Copyright © 2024  Bartłomiej Duda
License: GPL-3.0 License
"""
import os
import sys

from reversebox.common.logger import get_logger
from reversebox.image.image_decoder import ImageDecoder
from reversebox.image.image_formats import ImageFormats
from reversebox.image.pillow_wrapper import PillowWrapper
from reversebox.image.swizzling.swizzle_morton_dreamcast import unswizzle_morton_dreamcast
from reversebox.io_files.bytes_helper_functions import get_bits
from reversebox.io_files.file_handler import FileHandler

logger = get_logger(__name__)


def parse_dtex(dtex_file_path: str) -> bool:
    logger.info(f"Get image start, file_name={dtex_file_path}")

    image_decoder = ImageDecoder()
    wrapper = PillowWrapper()
    dtex_file = FileHandler(dtex_file_path, "rb", "little")
    dtex_file.open()

    file_id = dtex_file.read_bytes(4)
    if file_id != b'DTEX':
        raise Exception("Wrong dreamcast texture file signature!")
    image_width = dtex_file.read_uint16()
    image_height = dtex_file.read_uint16()
    image_type = dtex_file.read_uint32()
    image_size = dtex_file.read_uint32()

    pixel_format = get_bits(image_type, 3, 27)
    image_data = dtex_file.read_bytes(image_size)
    unswizzled_image_data: bytes = unswizzle_morton_dreamcast(image_data, image_width, image_height, 16)

    if pixel_format == 1:  # RGB565
        decoded_image_data: bytes = image_decoder.decode_image(
            unswizzled_image_data, image_width, image_height, ImageFormats.RGB565, "little"
        )
    else:
        raise Exception(f"Pixel format not supported! Pixel_format: {pixel_format}")

    pil_image = wrapper.get_pillow_image_from_rgba8888_data(decoded_image_data, image_width, image_height)
    pil_image.show()

    logger.info("Get image end")
    return True


def main():
    """
    Main function of this program.
    """
    logger.info("Starting main...")
    path_base: str = os.environ["IMG_PATH_BASE"]

    img_rel_path: str = "dtex_rgb565.tex"
    # img_rel_path: str = "dtex_yuv422.tex"


    final_path: str = os.path.join(path_base, img_rel_path)
    parse_dtex(final_path)
    logger.info("End of main... Program has been executed successfully!")
    sys.exit(0)


if __name__ == "__main__":
    main()
