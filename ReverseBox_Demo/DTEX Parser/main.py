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
    decoded_image_data: bytes = b''

    if pixel_format == 0:  # ARGB1555
        decoded_image_data: bytes = image_decoder.decode_image(
            unswizzled_image_data, image_width, image_height, ImageFormats.ARGB1555, "little"
        )
    elif pixel_format == 1:  # RGB565
        decoded_image_data: bytes = image_decoder.decode_image(
            unswizzled_image_data, image_width, image_height, ImageFormats.RGB565, "little"
        )
    elif pixel_format == 2:  # ARGB4444
        decoded_image_data: bytes = image_decoder.decode_image(
            unswizzled_image_data, image_width, image_height, ImageFormats.ARGB4444, "little"
        )
    elif pixel_format == 3:  # YUV422 (UYVY)
        decoded_image_data: bytes = image_decoder.decode_yuv_image(
            unswizzled_image_data, image_width, image_height, ImageFormats.YUV422_UYVY
        )
    elif pixel_format == 4:  # BUMPMAP
        decoded_image_data: bytes = image_decoder.decode_bumpmap_image(
            unswizzled_image_data, image_width, image_height, ImageFormats.BUMPMAP_SR
        )
    elif pixel_format == 5:  # PAL4BPP
        palette_file = FileHandler(dtex_file_path + ".pal", "rb", "little")
        palette_data = palette_file.read_whole_file_content()
        palette_data = palette_data[8:]
        decoded_image_data: bytes = image_decoder.decode_indexed_image(
            unswizzled_image_data, palette_data, image_width, image_height, ImageFormats.PAL4_RGB565  # TODO - not working
        )
    elif pixel_format == 6:  # PAL8BPP
        palette_file = FileHandler(dtex_file_path + ".pal", "rb", "little")
        palette_data = palette_file.read_whole_file_content()
        palette_data = palette_data[8:]
        decoded_image_data: bytes = image_decoder.decode_indexed_image(
            unswizzled_image_data, palette_data, image_width, image_height, ImageFormats.PAL8_RGB565  # TODO - not working
        )
    else:
        raise Exception(f"Pixel format not supported! Pixel_format: {pixel_format}")

    pil_image = wrapper.get_pillow_image_from_rgba8888_data(decoded_image_data, image_width, image_height)
    pil_image.show()

    logger.info("Get image end")
    return True


def get_final_path(img_rel_path: str) -> str:
    path_base: str = os.environ["IMG_PATH_BASE"]
    return os.path.join(path_base, img_rel_path)


def main():
    """
    Main function of this program.
    """
    logger.info("Starting main...")

    # parse_dtex(get_final_path("monkey_sample_RGB565.tex"))
    # parse_dtex(get_final_path("monkey_sample_ARGB1555.tex"))
    # parse_dtex(get_final_path("monkey_sample_ARGB4444.tex"))
    # parse_dtex(get_final_path("monkey_sample_YUV422_UYVY.tex"))
    # parse_dtex(get_final_path("monkey_sample_BUMPMAP.tex"))
    # parse_dtex(get_final_path("monkey_sample_PAL4BPP.tex"))
    # parse_dtex(get_final_path("monkey_sample_PAL8BPP.tex"))

    logger.info("End of main... Program has been executed successfully!")
    sys.exit(0)


if __name__ == "__main__":
    main()
