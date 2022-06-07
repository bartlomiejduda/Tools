"""
Copyright © 2022  Bartłomiej Duda
License: GPL-3.0 License
"""

# Program tested on Python 3.10.4

# Ver    Date        Author               Comment
# v0.1   08.06.2022  Bartlomiej Duda      -


import os
import struct
import sys
import argparse
from typing import Optional, Tuple
from logger import get_logger

logger = get_logger(__name__)

VERSION_NUM = "v0.1"
EXE_FILE_NAME = f"retro64_eco_tool_{VERSION_NUM}.exe"
PROGRAM_NAME = f"Retro64 ECO Tool {VERSION_NUM}"


def check_file(in_file_path: str, expected_extension: str, file_should_exist: bool, create_dirs=False,
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


def export_data(
        eco_file_path: str, encryption_key_str: str, xml_file_path: str
                ) -> Optional[tuple]:
    """
    Function for converting ECO to XML
    """
    logger.info("Starting export_data...")

    code, status = check_file(eco_file_path, ".ECO", True)
    if code != "OK":
        return code, status

    code, status = check_file(xml_file_path, ".XML", False)
    if code != "OK":
        return code, status

    eco_file = open(eco_file_path, "rb")
    xml_file = open(xml_file_path, "wb")

    try:
        encryption_key = int(encryption_key_str)
    except ValueError:
        return "NOT_INT_KEY_ERROR", f"Key {encryption_key_str} is not valid! Key must be integer value!"

    eco_file_size = os.path.getsize(eco_file_path)

    # decryption loop
    for i in range(eco_file_size):
        raw_byte = int(struct.unpack("B", eco_file.read(1))[0])
        decryption_result = (201 * encryption_key + 11) % 0x7FFF
        encryption_key = decryption_result
        decrypted_byte = raw_byte ^ (decryption_result % 0xFF)
        # print("enc_byte: ", encrypted_byte, " hex: ", "0x%02X" % int(encrypted_byte))
        xml_file.write(struct.pack("B", decrypted_byte))

    eco_file.close()
    xml_file.close()
    logger.info(f"File {xml_file_path} has been saved!")
    logger.info("Ending export_data...")
    return "OK", ""


def import_data(
    xml_file_path: str, encryption_key_str: str, eco_file_path: str
) -> Optional[tuple]:
    """
    Function for converting XML to ECO
    """
    logger.info("Starting import_data...")

    code, status = check_file(xml_file_path, ".XML", True)
    if code != "OK":
        return code, status

    code, status = check_file(eco_file_path, ".ECO", False)
    if code != "OK":
        return code, status

    xml_file = open(xml_file_path, "rt", encoding="utf8")
    eco_file = open(eco_file_path, "wb")

    try:
        encryption_key = int(encryption_key_str)
    except ValueError:
        return "NOT_INT_KEY_ERROR", f"Key {encryption_key_str} is not valid! Key must be integer value!"

    xml_file_size = os.path.getsize(xml_file_path)

    # encryption loop
    for i in range(xml_file_size):
        raw_byte = ord(xml_file.read(1))
        encryption_result = (201 * encryption_key + 11) % 0x7FFF
        encryption_key = encryption_result
        encrypted_byte = raw_byte ^ (encryption_result % 0xFF)
        # print("enc_byte: ", encrypted_byte, " hex: ", "0x%02X" % int(encrypted_byte))
        eco_file.write(struct.pack("B", encrypted_byte))

    eco_file.close()
    xml_file.close()

    logger.info(f"File {eco_file_path} has been saved!")
    logger.info("Ending import_data...")
    return "OK", ""


def main():
    """
    Main function of this program.
    """
    parser = argparse.ArgumentParser(prog=EXE_FILE_NAME, description=PROGRAM_NAME)
    # fmt: off
    parser.add_argument("-d", "--decrypt", metavar=("<eco_file_path>", "<encryption_key>", "<xml_file_path>"),
                        type=str, nargs=3, required=False, help="Decrypt data (convert ECO to XML)")

    parser.add_argument("-e", "--encrypt", metavar=("<xml_file_path>", "<encryption_key>", "<eco_file_path>"),
                        type=str, nargs=3, required=False, help="Encrypt data (convert XML to ECO)")
    # fmt: on

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    if args.decrypt is not None:
        code, status = export_data(args.decrypt[0], args.decrypt[1], args.decrypt[2])
        if code != "OK":
            logger.error(f"{code}: {status}")
            sys.exit(-1)
    elif args.encrypt is not None:
        code, status = import_data(args.encrypt[0], args.encrypt[1], args.encrypt[2])
        if code != "OK":
            logger.error(f"{code}: {status}")
            sys.exit(-2)

    logger.info("End of main... Program has been executed successfully!")
    sys.exit(0)


if __name__ == "__main__":
    main()
