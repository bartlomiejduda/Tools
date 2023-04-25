"""
Copyright © 2023  Bartłomiej Duda
License: GPL-3.0 License
"""

# Program tested on Python 3.11

# Ver    Date        Author               Comment
# v0.1   12.04.2023  Bartlomiej Duda      -
# v0.2   23.04.2023  Bartlomiej Duda      Add ReverseBox Translation Handler

from reversebox.common.logger import get_logger
from reversebox.io_files.translation_text_handler import TranslationTextHandler
from translation_memory import translation_memory

logger = get_logger(__name__)


# Adjust parameters below before using this tool!
bin_file_path: str = "C:\\EMULACJA\\AA_GRY_PS1\\Tail Concerto\\OUT\\DATA.BIN"
po_file_path: str = "C:\\EMULACJA\\AA_GRY_PS1\\Tail Concerto\\OUT\\DATA.BIN.po"
option: int = 1  # 1 - export   /   2 - import


def main():
    translation_handler = TranslationTextHandler(
            translation_memory=translation_memory, file_path=bin_file_path
        )

    if option == 1 and translation_handler.export_all_text(po_file_path):
        logger.info("Text exported successfully!")
    elif option == 2 and translation_handler.import_all_text(po_file_path):
        logger.info("Text imported successfully!")
    else:
        logger.info("Error with export occurred.")


if __name__ == "__main__":
    main()
