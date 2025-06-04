"""
Copyright © 2025  Bartłomiej Duda
License: GPL-3.0 License
"""
import io

from reversebox.image.common import get_bc_image_data_size
from reversebox.image.image_decoder import ImageDecoder
from reversebox.image.image_encoder import ImageEncoder
from reversebox.image.image_formats import ImageFormats
from reversebox.image.pillow_wrapper import PillowWrapper
from reversebox.image.swizzling.swizzle_switch import unswizzle_switch, swizzle_switch

# Raw Image Edit - Example 1

# This example shows how you can use ReverseBox to edit raw image data in an unknown binary file.
# First you should run ImageHeat to get proper parameters like img_width, img_height and img_format.
# Once you have those, you can adjust this example code for your needs and then do the following:

# 1. Use "export_image" function to save your image as DDS file
# 2. Edit your image in image-editing software like GIMP
# 3. Use "import_image" function to import back raw image data to a binary file
# 4. Test your changes in game that you're trying to mod


def export_image():
    print("Starting export...")
    image_file = open("files\\001cee1b.ctxr", "rb")
    image_file.seek(512)
    img_width: int = 960
    img_height: int = 128
    image_format: ImageFormats = ImageFormats.BC3_DXT5
    image_data_size: int = get_bc_image_data_size(img_height, img_width, image_format)
    image_data: bytes = image_file.read(image_data_size)

    image_data = unswizzle_switch(image_data, img_width, img_height, bytes_per_block=4, block_height=4)
    image_data = ImageDecoder().decode_compressed_image(image_data, img_width, img_height, image_format)
    pil_image = PillowWrapper().get_pillow_image_from_rgba8888_data(image_data, img_width, img_height)
    pil_image.save("files\\001cee1b.dds")
    print("Export successful!")


def import_image():
    print("Starting import...")
    original_file = open("files\\001cee1b.ctxr", "rb")
    original_file_data = original_file.read()
    original_file.close()

    img_width: int = 960
    img_height: int = 128
    image_format: ImageFormats = ImageFormats.BC3_DXT5
    expected_image_data_size: int = get_bc_image_data_size(img_height, img_width, image_format)
    image_data: bytes = PillowWrapper().get_pil_rgba_data_for_import("files\\001cee1b.dds")
    image_data = ImageEncoder().encode_compressed_image(image_data, img_width, img_height, image_format)
    image_data = swizzle_switch(image_data, img_width, img_height, bytes_per_block=4, block_height=4)

    if expected_image_data_size != len(image_data):
        raise Exception("Wrong image data size!")

    memory_file = io.BytesIO(original_file_data)
    memory_file.seek(512)
    memory_file.write(image_data)
    memory_file.seek(0)
    output_data = memory_file.read()

    output_file = open("files\\001cee1b_2.ctxr", "wb")
    output_file.write(output_data)
    output_file.close()
    print("Import successful!")


if __name__ == '__main__':
    export_image()
    import_image()
