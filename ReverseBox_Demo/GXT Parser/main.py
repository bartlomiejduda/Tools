"""
Copyright © 2024  Bartłomiej Duda
License: GPL-3.0 License
"""
import os
import sys

from reversebox.common.common import convert_int_to_hex_string
from reversebox.common.logger import get_logger
from reversebox.image.image_decoder import ImageDecoder
from reversebox.image.image_formats import ImageFormats
from reversebox.image.pillow_wrapper import PillowWrapper
from reversebox.image.swizzling.swizzle_psvita_dreamcast import unswizzle_psvita_dreamcast
from reversebox.io_files.file_handler import FileHandler

logger = get_logger(__name__)


def parse_gxt(gxt_file_path: str) -> bool:
    logger.info(f"Get image start, file_name={gxt_file_path}")

    image_decoder = ImageDecoder()
    wrapper = PillowWrapper()
    gxt_file = FileHandler(gxt_file_path, "rb", "little")

    file_id = gxt_file.read_bytes(4)
    if file_id != b'GXT\x00':
        raise Exception("Wrong GXT texture file signature!")
    gxt_version = gxt_file.read_uint32()
    number_of_textures = gxt_file.read_uint32()
    header_size = gxt_file.read_uint32()
    gxt_total_size = gxt_file.read_uint32()
    number_of_p4_palettes = gxt_file.read_uint32()
    number_of_p8_palettes = gxt_file.read_uint32()
    padding = gxt_file.read_uint32()

    for i in range(number_of_textures):
        tex_data_offset = gxt_file.read_uint32()
        tex_data_size = gxt_file.read_uint32()
        palette_index = gxt_file.read_uint32()
        tex_flags = gxt_file.read_uint32()
        tex_type = gxt_file.read_uint32()
        tex_base_format = convert_int_to_hex_string(gxt_file.read_uint32())
        tex_width = gxt_file.read_uint16()
        tex_height = gxt_file.read_uint16()
        tex_mipmaps_count = gxt_file.read_uint16()
        padding = gxt_file.read_uint16()

        gxt_file.seek(tex_data_offset)
        tex_data: bytes = gxt_file.read_bytes(tex_data_size)

        if tex_type == 0:  # swizzled
            pass
            tex_data = unswizzle_psvita_dreamcast(tex_data, tex_width, tex_height, 32)

        if tex_base_format == '0x87000000':  # DXT5
            decoded_image_data = image_decoder.decode_compressed_image(
                tex_data, tex_width, tex_height, ImageFormats.DXT5)
        elif tex_base_format == '0xC001000':  # ARGB8888
            decoded_image_data = image_decoder.decode_image(
                tex_data, tex_width, tex_height, ImageFormats.BGRA8888)
        else:
            raise Exception(f"Not supported texture base format! Format: {tex_base_format}")

        logger.info(f"Tex type: {tex_type}")
        logger.info(f"Tex base format: {tex_base_format}")
        pil_image = wrapper.get_pillow_image_from_rgba8888_data(decoded_image_data, tex_width, tex_height)
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

    parse_gxt(get_final_path("monkey4.gxt"))
    # parse_gxt(get_final_path("monkey4_linear.gxt"))
    # parse_gxt(get_final_path("aa_font_dmg0.gxt"))
    # parse_gxt(get_final_path("logo_MAQL.gxt"))




    logger.info("End of main... Program has been executed successfully!")
    sys.exit(0)


if __name__ == "__main__":
    main()
