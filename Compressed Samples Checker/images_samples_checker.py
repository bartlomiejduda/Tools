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

logger = get_logger(__name__)


def decode_images() -> bool:
    """
    Decode images after decompressing samples in COMTYPE_SCANNER

    example variables:
    SAMPLES_PATH --> .\Desktop\game_name\COMPTYPE_SCANNER\OUT
    """

    logger.info(f"Starting decode_images")

    img_width = 128
    img_height = 128
    image_format = ImageFormats.RGBA8888
    image_decoder = ImageDecoder()
    wrapper = PillowWrapper()

    checked_samples_counter: int = 0
    output_samples_path = get_decompressed_samples_dir_path()

    for filename in os.listdir(output_samples_path):
        f_path = os.path.join(output_samples_path, filename)
        out_path = f_path + ".png"
        if os.path.isfile(f_path):
            sample_file = open(f_path, "rb")
            checked_samples_counter += 1
            sample_image_data = sample_file.read()
            sample_file.close()
            logger.info(out_path)

            decoded_image_data: bytes = image_decoder.decode_image(
                sample_image_data, img_width, img_height, image_format
            )
            pil_image = wrapper.get_pillow_image_from_rgba8888_data(decoded_image_data, img_width, img_height)
            pil_image.save(out_path)

    logger.info(f"Checked samples count: {checked_samples_counter}")
    logger.info("No file matches! Exiting!")
    return False  # no match has been found


def get_decompressed_samples_dir_path() -> str:
    return os.environ["SAMPLES_PATH"]


def main():
    """
    Main function of this program.
    """
    logger.info("Starting main...")

    decode_images()

    logger.info("End of main... Program has been executed successfully!")
    sys.exit(0)


if __name__ == "__main__":
    main()
