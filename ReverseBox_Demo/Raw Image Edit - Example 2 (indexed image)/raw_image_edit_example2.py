"""
Copyright © 2025  Bartłomiej Duda
License: GPL-3.0 License
"""
import io

from reversebox.image.image_decoder import ImageDecoder
from reversebox.image.image_encoder import ImageEncoder
from reversebox.image.image_formats import ImageFormats
from reversebox.image.pillow_wrapper import PillowWrapper
from reversebox.image.swizzling.swizzle_ps2 import unswizzle_ps2_palette, swizzle_ps2_palette

# Raw Image Edit - Example 2

# This example shows how you can use ReverseBox to decode and encode indexed pixel formats.
# First you should run ImageHeat to get proper parameters like img_width, img_height and img_format.
# Once you have those, you can adjust this example code for your needs and then do the following:

# 1. Use "export_image" function to save your image as DDS file
# 2. Edit your image in image-editing software like GIMP
# 3. Use "import_image" function to import back raw image data to a binary file
# 4. Test your changes in game that you're trying to mod

img_width: int = 256
img_height: int = 256
image_format: ImageFormats = ImageFormats.PAL8
pal_format: ImageFormats = ImageFormats.RGBA8888


def export_image():
    print("Starting export...")
    image_file = open("files\\merlin_anotherfile.bin", "rb")
    pal_file = open("files\\merlin_anotherfile.pal", "rb")
    image_data: bytes = image_file.read()
    pal_data: bytes = pal_file.read()
    pal_data = unswizzle_ps2_palette(pal_data)

    image_data = ImageDecoder().decode_indexed_image(image_data, pal_data, img_width, img_height, image_format, pal_format)
    pil_image = PillowWrapper().get_pillow_image_from_rgba8888_data(image_data, img_width, img_height)
    pil_image.save("files\\merlin_image.dds")
    print("Export successful!")


def import_image():
    print("Starting import...")
    original_file = open("files\\merlin_anotherfile.bin", "rb")
    original_file_data = original_file.read()
    original_file.close()

    image_data: bytes = PillowWrapper().get_pil_rgba_data_for_import("files\\merlin_image.dds")
    image_data, palette_data = ImageEncoder().encode_indexed_image(image_data, img_width, img_height, image_format, pal_format, 256)
    palette_data = swizzle_ps2_palette(palette_data)

    memory_file = io.BytesIO(original_file_data)
    memory_file.write(image_data)
    memory_file.seek(0)
    output_data = memory_file.read()

    output_file = open("files\\merlin_anotherfile2.bin", "wb")
    output_file.write(output_data)
    output_file.close()

    output_pal_file = open("files\\merlin_anotherfile2.pal", "wb")
    output_pal_file.write(palette_data)
    output_pal_file.close()
    print("Import successful!")


if __name__ == '__main__':
    export_image()
    import_image()
