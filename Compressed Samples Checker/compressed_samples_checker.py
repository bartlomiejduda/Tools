"""
Copyright © 2024  Bartłomiej Duda
License: GPL-3.0 License
"""
import os
import sys

from reversebox.common.logger import get_logger

logger = get_logger(__name__)


def check_file_match(header_size: int = 30) -> bool:
    """
    Check if one of the decompressed samples from COMPTYPE_SCANNER
    is identical as the provided decompressed sample.
    Check window is set by "header_size" input parameter.

    example variables:
    SAMPLES_PATH --> .\Desktop\RS\COMPTYPE_SCANNER\OUT
    DECOMPRESSED_FILE_PATH --> .\Desktop\RS\CRICKS.RS  (decompressed file)
    """

    logger.info(f"Starting check_file_match")
    checked_samples_counter: int = 0
    output_samples_path = get_decompressed_samples_dir_path()
    decompressed_file_path = get_decompressed_sample_path()

    decompressed_file = open(decompressed_file_path, "rb")
    decompressed_file_header = decompressed_file.read(header_size)
    decompressed_file.close()

    for filename in os.listdir(output_samples_path):
        f_path = os.path.join(output_samples_path, filename)
        if os.path.isfile(f_path):
            sample_file = open(f_path, "rb")
            checked_samples_counter += 1
            sample_file_header = sample_file.read(header_size)
            if sample_file_header == decompressed_file_header:
                logger.info(f"Files match! Found file: {filename}")
                return True
            else:
                logger.info(f"No match for sample file: {filename}")

    logger.info(f"Checked samples count: {checked_samples_counter}")
    logger.info("No file matches! Exiting!")
    return False  # no match has been found


def get_decompressed_samples_dir_path() -> str:
    return os.environ["SAMPLES_PATH"]


def get_decompressed_sample_path() -> str:
    return os.environ["DECOMPRESSED_FILE_PATH"]


def main():
    """
    Main function of this program.
    """
    logger.info("Starting main...")

    check_file_match()

    logger.info("End of main... Program has been executed successfully!")
    sys.exit(0)


if __name__ == "__main__":
    main()
