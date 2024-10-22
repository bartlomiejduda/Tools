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
from reversebox.image.swizzling.swizzle_ps4 import unswizzle_ps4
from reversebox.io_files.bytes_helper_functions import get_bits
from reversebox.io_files.file_handler import FileHandler

logger = get_logger(__name__)


def parse_tex(tex_file_path: str) -> bool:
    logger.info(f"Get image start, file_name={tex_file_path}")

    image_decoder = ImageDecoder()
    pillow_wrapper = PillowWrapper()
    tex_file = FileHandler(tex_file_path, "rb", "little")

    signature = tex_file.read_bytes(4)
    if signature != b'TEX\x00':
        raise Exception("Wrong MT Framework texture file signature!")
    value1 = tex_file.read_uint32()
    value2 = tex_file.read_uint32()

    format_version = get_bits(value1, 11, 0)
    unknown1 = get_bits(value1, 11, 12)
    size_shift = get_bits(value1, 3, 24)
    cube_map = get_bits(value1, 3, 28)

    mipmap_count = get_bits(value2, 5, 0)
    img_width = get_bits(value2, 12, 6)
    img_height = get_bits(value2, 12, 19)

    texture_count = tex_file.read_uint8()
    color_type = tex_file.read_uint8()  # 24 - DXT5 (PS4 Swizzled?)
    unknown2 = tex_file.read_uint16()
    unk2_1 = get_bits(unknown2, 12, 0)
    unk2_2 = get_bits(unknown2, 3, 13)

    if format_version == 154:  # Dragon's Dogma: Dark Arisen (PS4)
        header_size = 32
        tex_file.seek(header_size)
        image_size = tex_file.get_file_size() - header_size
        image_data = tex_file.read_bytes(image_size)
        unswizzled_image_data = unswizzle_ps4(
            image_data, img_width, img_height, 8
        )

        decoded_image_data: bytes = image_decoder.decode_compressed_image(
            unswizzled_image_data, img_width, img_height, ImageFormats.DXT5
        )
        pil_image = pillow_wrapper.get_pillow_image_from_rgba8888_data(decoded_image_data, img_width, img_height)
        pil_image.show()
    else:
        raise Exception(f"Unsupported TEX format version: {format_version}!")

    return True


def get_final_path(img_rel_path: str) -> str:
    path_base: str = os.environ["IMG_PATH_BASE"]
    return os.path.join(path_base, img_rel_path)


def main():
    """
    Main function of this program.
    """
    logger.info("Starting main...")

    parse_tex(get_final_path("word_ID_eng.texture"))  # Dragon's Dogma: Dark Arisen (PS4)

    logger.info("End of main... Program has been executed successfully!")
    sys.exit(0)


if __name__ == "__main__":
    main()
