"""
Copyright © 2022  Bartłomiej Duda
License: GPL-3.0 License
"""

# Program tested on Python 3.10.4

# Ver    Date        Author               Comment
# v0.1   05.06.2022  Bartlomiej Duda      -
# v0.2   09.06.2022  Bartlomiej Duda      Added import function, added TranslationEntry class


import os
import struct
import sys
import argparse
from dataclasses import dataclass
from typing import Optional, Tuple
from logger import get_logger

logger = get_logger(__name__)

VERSION_NUM = "v0.2"
EXE_FILE_NAME = f"gameloft_text_tool_{VERSION_NUM}.exe"
PROGRAM_NAME = f"Gameloft Text Tool {VERSION_NUM}"


@dataclass
class TranslationEntry:
    translation_start_offset: int
    translation_end_offset: int
    translation_text: str
    translation_text_length: int


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


def export_data(off_file_path: str, bin_file_path: str, ini_file_path) -> Optional[tuple]:
    """
    Function for exporting data from BIN/OFF files
    """
    logger.info("Starting export_data...")

    code, status = check_file(off_file_path, ".OFF", True)
    if code != "OK":
        return code, status

    code, status = check_file(bin_file_path, ".BIN", True)
    if code != "OK":
        return code, status

    code, status = check_file(ini_file_path, ".INI", False)
    if code != "OK":
        return code, status

    bin_file = open(bin_file_path, "rb")
    off_file = open(off_file_path, "rb")
    ini_file = open(ini_file_path, "wt", encoding="utf8")

    number_of_entries = int(struct.unpack("<H", off_file.read(2))[0])

    offset_array = []
    for i in range(number_of_entries):
        offset_array.append(struct.unpack("<L", off_file.read(4))[0])

    # extraction loop
    current_offset = 0
    for i in range(number_of_entries):
        string_start_offset = current_offset
        string_end_offset = offset_array[i]
        string_length = string_end_offset - current_offset
        current_offset = string_start_offset + string_length

        bin_file.seek(string_start_offset)
        string_text = bin_file.read(string_length).decode("utf8").rstrip("\x00").replace("\n", "\\n")
        translation_entry = "TEXT_TO_TRANSLATE_" + str(i + 1) + "=" + string_text + "\n"
        ini_file.write(translation_entry)

    ini_file.close()
    bin_file.close()
    off_file.close()
    logger.info(f"File {ini_file_path} has been saved.")
    logger.info("Ending export_data...")
    return "OK", ""


def import_data(
        off_file_path: str, bin_file_path: str, ini_file_path: str
) -> Optional[tuple]:
    """
    Function for importing data to BIN/OFF files
    """
    logger.info("Starting import_data...")

    code, status = check_file(off_file_path, ".OFF", False)
    if code != "OK":
        return code, status

    code, status = check_file(bin_file_path, ".BIN", False)
    if code != "OK":
        return code, status

    code, status = check_file(ini_file_path, ".INI", True)
    if code != "OK":
        return code, status

    ini_file = open(ini_file_path, "rt", encoding="utf8")
    bin_file = open(bin_file_path, "wb")
    off_file = open(off_file_path, "wb")

    number_of_lines = 0
    entries_array = []
    current_offset: int = 0

    # import loop
    for line in ini_file:
        number_of_lines += 1

        translation_start_offset = current_offset
        translation_text = (line.split("=")[-1].rstrip("\n") + "\x00\x00").replace("\\n", "\n")
        translation_text_length = len(translation_text.encode("utf8"))
        translation_end_offset = translation_start_offset + translation_text_length
        current_offset = translation_end_offset

        translation_entry = TranslationEntry(
            translation_start_offset=translation_start_offset,
            translation_text=translation_text,
            translation_text_length=translation_text_length,
            translation_end_offset=translation_end_offset
        )

        entries_array.append(translation_entry)

    # writing output data to BIN/OFF files
    off_file.write(struct.pack("<H", number_of_lines))
    for entry in entries_array:
        off_file.write(struct.pack("<L", entry.translation_end_offset))
        bin_file.write(entry.translation_text.encode("utf8"))

    off_file.close()
    bin_file.close()
    ini_file.close()
    logger.info(f"File {bin_file_path} has been saved.")
    logger.info(f"File {off_file_path} has been saved.")
    logger.info("Ending import_data...")
    return "OK", ""


def main():
    """
    Main function of this program.
    """
    parser = argparse.ArgumentParser(prog=EXE_FILE_NAME, description=PROGRAM_NAME)
    # fmt: off
    parser.add_argument("-e", "--exp", metavar=("<off_file_path>", "<bin_file_path>", "<ini_file_path>"),
                        type=str, nargs=3, required=False, help="Extract data (convert BIN/OFF to INI)")

    parser.add_argument("-i", "--imp", metavar=("<new_off_file_path>", "<new_bin_file_path>", "<ini_file_path>"),
                        type=str, nargs=3, required=False, help="Import data (convert INI to BIN/OFF)")
    # fmt: on

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    if args.exp is not None:
        code, status = export_data(args.exp[0], args.exp[1], args.exp[2])
        if code != "OK":
            logger.error(f"{code}: {status}")
            sys.exit(-1)
    elif args.imp is not None:
        code, status = import_data(args.imp[0], args.imp[1], args.imp[2])
        if code != "OK":
            logger.error(f"{code}: {status}")
            sys.exit(-2)

    logger.info("End of main... Program has been executed successfully!")
    sys.exit(0)


if __name__ == "__main__":
    main()
