"""
Copyright © 2025  Bartłomiej Duda
License: GPL-3.0 License
"""
import os

from reversebox.common.logger import get_logger
from reversebox.compression.compression_re_tiyoruga_dat import decompress_data
from reversebox.io_files.file_handler import FileHandler

logger = get_logger(__name__)


def unpack_DAT(dat_file_path: str, output_path: str) -> bool:
    logger.info(f"Starting unpack_DAT")
    dat_file = FileHandler(dat_file_path, "rb", "little")
    dat_file.open()

    number_of_files: int = dat_file.read_uint32()
    archive_size: int = dat_file.read_uint32()

    for i in range(number_of_files):
        file_compressed_size: int = dat_file.read_uint32()
        file_uncompressed_size: int = dat_file.read_uint32()
        file_path: str = dat_file.read_bytes(300).decode("utf8").rstrip('\x00')
        file_data: bytes = decompress_data(dat_file.read_bytes(file_compressed_size), file_uncompressed_size)

        if len(file_data) != file_uncompressed_size:
            raise Exception("Decompression error! Wrong decompressed file size!")

        output_file_path = os.path.join(output_path, file_path)

        if not os.path.exists(os.path.dirname(output_file_path)):
            os.makedirs(os.path.dirname(output_file_path))

        output_file = open(output_file_path, "wb")
        output_file.write(file_data)
        output_file.close()
        logger.info(f"Unpacked {i+1}) {output_file_path}")

    if dat_file.get_position() != archive_size:
        raise Exception("Error processing archive! Not all data unpacked!")

    logger.info("Finished unpacking!")
    return True


if __name__ == '__main__':
    unpack_DAT('C:\\Users\\User\\Desktop\\DAT\\Data1.dat', 'C:\\Users\\User\\Desktop\\DAT\\out')
