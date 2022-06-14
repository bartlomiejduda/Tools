"""
Copyright © 2022  Bartłomiej Duda
License: GPL-3.0 License
"""

# Program tested on Python 3.10.4

# Ver    Date        Author               Comment
# v0.1   14.06.2022  Bartlomiej Duda      -


import os
import struct
import sys
import argparse
# import jcalg1
# import ctypes
from typing import Optional, Tuple
from logger import get_logger

logger = get_logger(__name__)

VERSION_NUM = "v0.1"
EXE_FILE_NAME = f"retro64_lev_tool_{VERSION_NUM}.exe"
PROGRAM_NAME = f"Retro64 LEV Tool {VERSION_NUM}"


def check_file(
    in_file_path: str,
    expected_extension: str,
    file_should_exist: bool,
    create_dirs=False,
) -> Tuple[str, str]:
    if file_should_exist:
        if not os.path.isfile(in_file_path):
            return "NOT_FILE_ERROR", f"{in_file_path} is not a valid input file path!"

    in_file_extension = os.path.splitext(in_file_path)[1]
    if in_file_extension.upper() != expected_extension.upper():
        return (
            f"NOT_{expected_extension.upper()}_ERROR",
            f"{in_file_path} is not a valid {expected_extension.upper()} file!",
        )

    if create_dirs:
        if not os.path.exists(os.path.dirname(in_file_path)):
            try:
                os.makedirs(os.path.dirname(in_file_path))
            except FileNotFoundError:
                return "CANT_CREATE_DIR_ERROR", "Can't create output directory!"

    return "OK", ""


def export_data(lev_file_path: str, xml_file_path: str) -> Optional[tuple]:
    """
    Function for converting LEV to XML
    """
    logger.info("Starting export_data...")

    code, status = check_file(lev_file_path, ".LEV", True)
    if code != "OK":
        return code, status

    code, status = check_file(xml_file_path, ".XML", False)
    if code != "OK":
        return code, status

    lev_file = open(lev_file_path, "rb")
    xml_file = open(xml_file_path, "wb")

    lev_file_size = os.path.getsize(lev_file_path)

    # data read loop
    encrypted_bytes_array = []
    for i in range(lev_file_size):
        encrypted_byte = int(struct.unpack("B", lev_file.read(1))[0])
        encrypted_bytes_array.append(encrypted_byte)

    # decryption loop
    for i in range(lev_file_size):
        result = ~encrypted_bytes_array[i] & 0xFF
        # print("result: ", result, " hex: ", "0x%02X" % int(result))
        encrypted_bytes_array[i] = result

    # check if file is compressed
    header_byte1 = struct.pack("B", encrypted_bytes_array[0])
    header_byte2 = struct.pack("B", encrypted_bytes_array[1])
    check_value = struct.unpack("<H", header_byte1 + header_byte2)[0]
    if check_value == 17226:  # 4A 43 ("JC" - JCALG1 compression signature)
        size_byte1 = struct.pack("B", encrypted_bytes_array[2])
        size_byte2 = struct.pack("B", encrypted_bytes_array[3])
        size_byte3 = struct.pack("B", encrypted_bytes_array[4])
        size_byte4 = struct.pack("B", encrypted_bytes_array[5])
        data_size = struct.unpack("<L", size_byte1 + size_byte2 + size_byte3 + size_byte4)[0]
        #print("data_size: ", data_size, " hex: ", "0x%02X" % int(data_size))
    else:
        data_size = 0  # not compressed

    # data_size += 4
    # print("data_size: ", data_size, " hex: ", "0x%02X" % int(data_size))

    # save decrypted data (but it may be compressed)
    for i in range(lev_file_size):
        xml_file.write(struct.pack("B", encrypted_bytes_array[i]))
    xml_file.close()

    # TODO - add decompression
    # # read decrypted data
    # decrypted_xml_file = open(xml_file_path, "rb")
    # decrypted_data = decrypted_xml_file.read()
    # decrypted_xml_file.close()

    # decompressed_data: bytes = b''
    # jcalg_library = ctypes.cdll.LoadLibrary(".\\JCALG1.dll")

    # src: ctypes.c_void_p = decrypted_data
    # dest: ctypes.c_void_p = b''

    # result1: ctypes.c_uint32 = jcalg_library.JCALG1_Decompress_Fast(decrypted_data, decompressed_data)

    # decompressed_data = jcalg1.decompress(decrypted_data)
    # decompressed_xml_file = open(xml_file_path, "wb")
    # decompressed_xml_file.write(decompressed_data)
    # decompressed_xml_file.close()

    lev_file.close()

    logger.info(f"File {xml_file_path} has been saved!")
    logger.info("Ending export_data...")
    return "OK", ""


def import_data(
    xml_file_path: str, lev_file_path: str
) -> Optional[tuple]:
    """
    Function for converting XML to LEV
    """
    logger.info("Starting import_data...")
    # TODO - add import

    return "NOT_SUPPORTED", "Import is not supported yet!"


def main():
    """
    Main function of this program.
    """
    parser = argparse.ArgumentParser(prog=EXE_FILE_NAME, description=PROGRAM_NAME)
    # fmt: off
    parser.add_argument("-d", "--decrypt", metavar=("<lev_file_path>", "<xml_file_path>"),
                        type=str, nargs=2, required=False, help="Decrypt data (convert LEV to XML)")

    parser.add_argument("-e", "--encrypt", metavar=("<xml_file_path>", "<lev_file_path>"),
                        type=str, nargs=2, required=False, help="Encrypt data (convert XML to LEV)")
    # fmt: on

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    if args.decrypt is not None:
        code, status = export_data(args.decrypt[0], args.decrypt[1])
        if code != "OK":
            logger.error(f"{code}: {status}")
            sys.exit(-1)
    elif args.encrypt is not None:
        code, status = import_data(args.encrypt[0], args.encrypt[1])
        if code != "OK":
            logger.error(f"{code}: {status}")
            sys.exit(-2)

    logger.info("End of main... Program has been executed successfully!")
    sys.exit(0)


if __name__ == "__main__":
    main()
