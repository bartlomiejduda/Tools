"""
Copyright © 2026  Bartłomiej Duda
License: GPL-3.0 License
"""

import json
import os
from typing import List

from reversebox.common.logger import get_logger

from anubis_II_char_replacer import replace_chars_in_multiple_folders

# Program tested on Python 3.11.6
# Tool was made for Polish translation of "Anubis II" PC game

# Ver    Date        Author               Comment
# v1.0   18.10.2026  Bartlomiej Duda      Initial version (char replacer only)


logger = get_logger(__name__)

# fmt: off

if __name__ == '__main__':
    logger.info("Starting main...")
    operation_type: str = os.environ["OPERATION_TYPE"]  # EXPORT / IMPORT

    if operation_type == "EXPORT":
        pass  # TODO
    elif operation_type == "IMPORT":
        # TODO
        replace_extensions: List[str] = json.loads(os.environ["REPLACE_EXTENSIONS"])  # e.g. ["txt"]
        replace_folders: List[str] = json.loads(os.environ["REPLACE_FOLDERS"])
        replace_chars_in_multiple_folders(replace_extensions, replace_folders)
    else:
        logger.error(f"Not supported operation_type={operation_type}")

    logger.info("Exiting main...")
