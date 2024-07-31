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
from reversebox.image.swizzling.swizzle_bc import unswizzle_bc
from reversebox.io_files.file_handler import FileHandler

logger = get_logger(__name__)


def parse_tpl(tpl_file_path: str) -> bool:
    logger.info(f"Get image start, file_name={tpl_file_path}")

    image_decoder = ImageDecoder()
    wrapper = PillowWrapper()
    tpl_file = FileHandler(tpl_file_path, "rb", "big")
    tpl_file.open()

    file_id = tpl_file.read_bytes(4)
    if file_id != b'\x00\x20\xAF\x30':
        raise Exception("Wrong TPL file signature!")
    number_of_images = tpl_file.read_uint32()
    offset_of_image_table = tpl_file.read_uint32()

    for i in range(number_of_images):
        image_header_offset = tpl_file.read_uint32()
        palette_header_offset = tpl_file.read_uint32()

        # read image header
        tpl_file.seek(image_header_offset)
        image_height = tpl_file.read_uint16()
        image_width = tpl_file.read_uint16()
        image_format = tpl_file.read_uint32()
        image_data_offset = tpl_file.read_uint32()
        image_data = b''
        image_data_size = 0
        decoded_image_data = b''
        tpl_file.seek(image_data_offset)

        # read image_data
        if image_format == 0:  # I4
            image_data_size = (image_width * image_height) // 2
        elif image_format == 1:  # I8
            image_data_size = image_width * image_height
        elif image_format == 5:  # RGB5A3
            image_data_size = (image_width * image_height) * 2
        else:
            raise Exception("Not supported image type!")

        image_data = tpl_file.read_bytes(image_data_size)

        # unswizzle data
        if image_format == 0:
            image_data = unswizzle_bc(image_data, image_width, image_height, 8, 8, 4)
        elif image_format == 1:
            image_data = unswizzle_bc(image_data, image_width, image_height, 8, 4, 8)
        elif image_format == 5:
            image_data = unswizzle_bc(image_data, image_width, image_height, 4, 4, 16)

        if image_format == 0:  # I4
            decoded_image_data: bytes = image_decoder.decode_image(
                image_data, image_width, image_height, ImageFormats.N64_I4, "big"
            )
        elif image_format == 1:  # I8
            decoded_image_data: bytes = image_decoder.decode_image(
                image_data, image_width, image_height, ImageFormats.N64_I8, "big"
            )
        elif image_format == 5:  # RGB5A3
            decoded_image_data: bytes = image_decoder.decode_image(
                image_data, image_width, image_height, ImageFormats.N64_RGB5A3, "big"
            )

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

    img_rel_path: str = "RGB5A3\\gold_coin_16bits_128x128.tpl"
    # img_rel_path: str = "RGB5A3\\baby_luigi_16bits_64x64.tpl"
    # img_rel_path: str = "RGB5A3\\home_icon_56x56.tpl"
    # img_rel_path: str = "RGB5A3\\yoshi_16bits_64x64.tpl"
    # img_rel_path: str = "I4\\home_menu_title_368x40.tpl"
    # img_rel_path: str = "I8\\white_cursor_8bits_80x80.tpl"

    final_path: str = os.path.join(path_base, img_rel_path)
    parse_tpl(final_path)
    logger.info("End of main... Program has been executed successfully!")
    sys.exit(0)


if __name__ == "__main__":
    main()
