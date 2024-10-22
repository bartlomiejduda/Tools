"""
Copyright © 2024  Bartłomiej Duda
License: GPL-3.0 License
"""
import argparse
import os
import sys

from reversebox.common.logger import get_logger
from reversebox.image.image_decoder import ImageDecoder
from reversebox.image.image_formats import ImageFormats
from reversebox.image.pillow_wrapper import PillowWrapper
from reversebox.image.swizzling.swizzle_ps4 import unswizzle_ps4
from reversebox.io_files.bytes_helper_functions import get_bits
from reversebox.io_files.file_handler import FileHandler
from PIL import Image

logger = get_logger(__name__)


def convert_tex_to_dds(tex_file_path: str, dds_file_path: str) -> bool:
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
    color_type = tex_file.read_uint8()  # 24 - DXT5 (PS4 Swizzled)
    unknown2 = tex_file.read_uint16()
    unk2_1 = get_bits(unknown2, 12, 0)
    padding_flag = get_bits(unknown2, 3, 13)

    if texture_count > 1:
        raise Exception(f"Currently multiple-textures files are not supported! Texture_count: {texture_count}")

    if format_version == 154:  # Dragon's Dogma: Dark Arisen (PS4)
        header_size = 32
        tex_file.seek(header_size)
        image_size = tex_file.get_file_size() - header_size
        image_data = tex_file.read_bytes(image_size)

        if color_type == 24:
            unswizzled_image_data = unswizzle_ps4(
                image_data, img_width, img_height, 4, 4, 16
            )
            decoded_image_data: bytes = image_decoder.decode_compressed_image(
                unswizzled_image_data, img_width, img_height, ImageFormats.DXT5
            )
        else:
            raise Exception(f"Unsupported color_type: {color_type}!")
        pil_image = pillow_wrapper.get_pillow_image_from_rgba8888_data(decoded_image_data, img_width, img_height)
        pil_image.save(dds_file_path)
    else:
        raise Exception(f"Unsupported TEX format version: {format_version}!")

    logger.info("Image converted successfully!")
    return True


def convert_dds_to_tex(old_tex_file_path: str, dds_file_path: str, new_tex_file_path) -> bool:
    logger.info(f"Get image start, file_name={dds_file_path}")
    pillow_wrapper = PillowWrapper()
    pillow_image = Image.open(dds_file_path)
    image_data: bytes = pillow_wrapper.get_image_data_from_pillow_image(pillow_image)

    old_tex_file = FileHandler(old_tex_file_path, "rb", "little")
    header = old_tex_file.read_bytes(32)

    old_tex_file.seek(0)
    signature = old_tex_file.read_bytes(4)
    if signature != b'TEX\x00':
        raise Exception("Wrong MT Framework texture file signature!")

    old_tex_file.seek(13)
    color_type = old_tex_file.read_uint8()  # 24 - DXT5 (PS4 Swizzled)
    if color_type != 24:
        raise Exception(f"Unsupported color_type: {color_type}!")

    # TODO - add encode DXT5 logic here

    # TODO - add swizzling logic here (from ReverseBox)

    # TODO - add save TEX logic here

    return True


def get_final_path(img_rel_path: str) -> str:
    path_base: str = os.environ["IMG_PATH_BASE"]
    return os.path.join(path_base, img_rel_path)


VERSION_NUM = "v1.0"
EXE_FILE_NAME = f"mt_framework_tex_converter_{VERSION_NUM}.exe"
PROGRAM_NAME = f'MT Framework TEX Converter {VERSION_NUM}'


def main():
    """
    Main function of this program.
    """
    logger.info("Starting main...")

    # convert_tex_to_dds(get_final_path("word_ID_eng.texture"), get_final_path("out.dds"))  # Dragon's Dogma: Dark Arisen (PS4)

    parser = argparse.ArgumentParser(prog=EXE_FILE_NAME,
                                     description=PROGRAM_NAME)
    # fmt: off
    parser.add_argument('-e', '--ext', metavar='<tex_file_path>, <dds_file_path>',
                        type=str, nargs=2, required=False, help='Convert TEX to DDS')
    parser.add_argument('-i', '--imp', metavar='<old_tex_file_path>, <dds_file_path> <new_tex_file_path>',
                        type=str, nargs=3, required=False, help='Convert DDS to TEX')
    # fmt: on

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    if args.ext is not None:
        result = convert_tex_to_dds(args.ext[0], args.ext[1])
        if not result:
            logger.error("Error while converting data!")
            sys.exit(-1)
    elif args.imp is not None:
        result = convert_dds_to_tex(args.imp[0], args.imp[1], args.imp[2])
        if not result:
            logger.error("Error while converting data!")
            sys.exit(-1)
    else:
        parser.print_help()
        sys.exit(1)

    logger.info("End of main... Program has been executed successfully!")
    sys.exit(0)


if __name__ == "__main__":
    main()
