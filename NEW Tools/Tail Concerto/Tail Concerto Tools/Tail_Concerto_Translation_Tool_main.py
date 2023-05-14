"""
Copyright © 2023  Bartłomiej Duda
License: GPL-3.0 License
"""

# Program tested on Python 3.11

# Ver    Date        Author               Comment
# v0.1   12.04.2023  Bartlomiej Duda      -
# v0.2   23.04.2023  Bartlomiej Duda      Add ReverseBox Translation Handler
# v0.3   25.04.2023  Bartlomiej Duda      Add more entries
# v0.4   01.05.2023  Bartlomiej Duda      Add more entries, update ReverseBox, add character mapping
# v0.5   01.05.2023  Bartlomiej Duda      Add more entries, List reverse
# v0.6   09.05.2023  Bartlomiej Duda      Update to ReverseBox 0.6.0
import logging
from typing import List

from reversebox.common.logger import get_logger
from reversebox.io_files.mod_handler import ModHandler
from reversebox.io_files.translation_text_handler import TranslationTextHandler, TranslationEntry, \
    windows_1250_pl_no_accents_character_mapping, check_translation_entries

from mod_memory import mod_memory
from translation_memory import translation_memory

logger = get_logger(__name__)


# Adjust parameters below before using this tool!
# Read README file for more details
bin_file_path: str = "C:\\EMULACJA\\AA_GRY_PS1\\Tail Concerto\\OUT\\DATA.BIN"
po_file_path: str = "C:\\EMULACJA\\AA_GRY_PS1\\Tail Concerto\\OUT\\DATA.BIN.po"
out_file_path: str = "C:\\EMULACJA\\AA_GRY_PS1\\Tail Concerto\\OUT\\ModHandler_OUT\\"

option: int = 3     # 1 - export text   /   2 - import text
                    # 3 - export files


def get_datetime_string() -> str:
    return "29/04/2023 20:06:57"


def get_tail_concerto_encoding() -> str:
    return "windows-1250"


def tail_concerto_import_transform(input_bytes: bytes) -> bytes:
    for key, value in windows_1250_pl_no_accents_character_mapping.items():
        input_bytes = input_bytes.replace(key, value)
    return input_bytes


def main():
    reversed_translation_memory: List[TranslationEntry] = list(reversed(translation_memory))
    if not check_translation_entries(reversed_translation_memory):
        logger.error("Error while checking translation memory")
        return
    translation_handler = TranslationTextHandler(
            translation_memory=reversed_translation_memory, file_path=bin_file_path,
            global_import_function=tail_concerto_import_transform,
        )

    mod_handler = ModHandler(
        mod_memory=mod_memory,
        archive_file_path=bin_file_path,
        log_level=logging.INFO
    )

    if option == 1 and translation_handler.export_all_text(po_file_path, creation_date_string=get_datetime_string(),
                                                           revision_date_string=get_datetime_string(),
                                                           encoding=get_tail_concerto_encoding()):
        logger.info("Text exported successfully!")
    elif option == 2 and translation_handler.import_all_text(po_file_path, create_backup_file=False,
                                                             encoding=get_tail_concerto_encoding()):
        logger.info("Text imported successfully!")
    elif option == 3 and mod_handler.export_all_files(out_file_path):
        logger.info("Game data exported successfully!")
    else:
        logger.error("Wrong option or some error occurred! See the logs for more details.")


if __name__ == "__main__":
    main()
