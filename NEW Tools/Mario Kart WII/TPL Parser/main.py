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


image_formats: dict = {
    # code: (format_name, bpp, block_width, block_height)
    0x00: ("i4", 4, 8, 8),
    0x01: ("i8", 8, 8, 4),
    0x02: ("ia4", 8, 8, 4),
    0x03: ("ia8", 16, 4, 4),
    0x04: ("rgb565", 16, 4, 4),
    0x05: ("rgb5a3", 16, 4, 4),
    0x06: ("rgba32", 32, 4, 4),
    0x08: ("c4", 4, 8, 8),
    0x09: ("c8", 8, 8, 4),
    0x0A: ("c14x2", 16, 4, 4),
    0x0E: ("cmpr", 4, 8, 8)
}


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
        palette_data = b''
        palette_format = -1
        decoded_image_data = b''

        format_name, bpp, block_width, block_height = image_formats[image_format]

        # read palette data
        if image_format >= 8:
            tpl_file.seek(palette_header_offset)
            entry_count = tpl_file.read_uint16()
            tpl_file.read_uint8()
            tpl_file.read_uint8()
            palette_format = tpl_file.read_uint32()
            palette_data_offset = tpl_file.read_uint32()
            palette_size = entry_count * 2  # all palettes are 16 bpp?
            tpl_file.seek(palette_data_offset)
            palette_data = tpl_file.read_bytes(palette_size)

        # read image_data
        tpl_file.seek(image_data_offset)

        def _get_image_size(img_width, img_height, bw, bh, bpp_value) -> int:
            return bpp_value * ((img_width + bw - 1) // bw * bw) * ((img_height + bh - 1) // bh * bh) // 8

        image_data_size = _get_image_size(image_width, image_height, block_width, block_height, bpp)
        image_data = tpl_file.read_bytes(image_data_size)

        # unswizzle data
        image_data = unswizzle_bc(image_data, image_width, image_height, block_width, block_height, bpp)

        if image_format == 0:  # I4
            decoded_image_data: bytes = image_decoder.decode_image(
                image_data, image_width, image_height, ImageFormats.N64_I4, "big"
            )
        elif image_format == 1:  # I8
            decoded_image_data: bytes = image_decoder.decode_image(
                image_data, image_width, image_height, ImageFormats.N64_I8, "big"
            )
        elif image_format == 2:  # IA4
            decoded_image_data: bytes = image_decoder.decode_image(
                image_data, image_width, image_height, ImageFormats.N64_IA4, "big"
            )
        elif image_format == 3:  # IA8
            decoded_image_data: bytes = image_decoder.decode_image(
                image_data, image_width, image_height, ImageFormats.N64_IA8, "big"
            )
        elif image_format == 5:  # RGB5A3
            decoded_image_data: bytes = image_decoder.decode_image(
                image_data, image_width, image_height, ImageFormats.N64_RGB5A3, "big"
            )
        elif image_format == 8:  # C4
            if palette_format == 0:  # IA8
                decoded_image_data: bytes = image_decoder.decode_indexed_image(
                    image_data, palette_data, image_width, image_height, ImageFormats.PAL4_IA8, "big", "big"
                )
            elif palette_format == 1:  # RGB565
                decoded_image_data: bytes = image_decoder.decode_indexed_image(
                    image_data, palette_data, image_width, image_height, ImageFormats.PAL4_RGB565, "big", "big"
                )
            elif palette_format == 2:  # RGB5A3
                decoded_image_data: bytes = image_decoder.decode_indexed_image(
                    image_data, palette_data, image_width, image_height, ImageFormats.PAL4_RGB5A3, "big", "big"
                )
            else:
                raise Exception(f"Not supported palette format! Palette format: {palette_format}")
        elif image_format == 9:  # C8
            if palette_format == 0:  # IA8
                decoded_image_data: bytes = image_decoder.decode_indexed_image(
                    image_data, palette_data, image_width, image_height, ImageFormats.PAL8_IA8, "big", "big"
                )
            elif palette_format == 1:  # RGB565
                decoded_image_data: bytes = image_decoder.decode_indexed_image(
                    image_data, palette_data, image_width, image_height, ImageFormats.PAL8_RGB565, "big", "big"
                )
            elif palette_format == 2:  # RGB5A3
                decoded_image_data: bytes = image_decoder.decode_indexed_image(
                    image_data, palette_data, image_width, image_height, ImageFormats.PAL8_RGB5A3, "big", "big"
                )
            else:
                raise Exception(f"Not supported palette format! Palette format: {palette_format}")

        elif image_format == 10:  # C14X2
            if palette_format == 0:  # IA8
                decoded_image_data: bytes = image_decoder.decode_indexed_image(
                    image_data, palette_data, image_width, image_height, ImageFormats.PAL16_IA8, "big", "big"
                )
            elif palette_format == 1:  # RGB565
                decoded_image_data: bytes = image_decoder.decode_indexed_image(
                    image_data, palette_data, image_width, image_height, ImageFormats.PAL16_RGB565, "big", "big"
                )
            elif palette_format == 2:  # RGB5A3
                decoded_image_data: bytes = image_decoder.decode_indexed_image(
                    image_data, palette_data, image_width, image_height, ImageFormats.PAL16_RGB5A3, "big", "big"
                )
            else:
                raise Exception(f"Not supported palette format! Palette format: {palette_format}")
        else:
            raise Exception(f"Unsupported image format! Format: {image_format}")

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
    # img_rel_path: str = "IA4\\white_black_8bits_32x32.tpl"
    # img_rel_path: str = "IA8\\grey_smiley_face_16bits_64x64.tpl"
    # img_rel_path: str = "IA8\\box_16bits_256x256.tpl"
    # img_rel_path: str = "C4\\canada_flag_4bits_60x40.tpl"
    # img_rel_path: str = "C4\\japan_flag_4bits_60x40.tpl"
    # img_rel_path: str = "C8\\korea_flag_8bits_60x40.tpl"
    # img_rel_path: str = "C14X2\\cayman_islands_blue_flag_14bits_60x40.tpl"

    final_path: str = os.path.join(path_base, img_rel_path)
    parse_tpl(final_path)
    logger.info("End of main... Program has been executed successfully!")
    sys.exit(0)


if __name__ == "__main__":
    main()
