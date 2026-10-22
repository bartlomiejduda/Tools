"""
Copyright © 2026  Bartłomiej Duda
License: GPL-3.0 License
"""

import json
import os
import glob
import shutil
from typing import List

from reversebox.common.logger import get_logger

logger = get_logger(__name__)

# fmt: off


def replace_chars_recursive_for_single_file_type(extension: str, replace_folder) -> None:
    logger.info("Starting replacing chars for extension=" + extension + " and folder=" + replace_folder)
    os.chdir(replace_folder)
    file_set = glob.glob(r'*.' + extension)
    file_set += glob.glob(r'*\*.' + extension)
    fold = '*\\'
    fold2 = ''
    for i in range(100):
        fold2 += fold
        file_set += glob.glob(fold2 + '*.' + extension)
    for file in file_set:
        txt_path = os.path.abspath(file)

        temp_path = os.path.dirname(txt_path)
        temp_filename = txt_path.split('\\')[-1].split('.')[0]
        temp_path += '\\' + temp_filename + '_temp.txt'

        temp_file = open(temp_path, 'wb+')
        txt_file = open(txt_path, 'rb')

        # All files should be in latin-1 for DDI games
        for line in txt_file:
            line = (
                line

                # TODO
                # big chars
                .replace(b'\xAF', b'\xC1')  # Ż -> a
                .replace(b'\xAE', b'\xC1')  # Ó -> b
                .replace(b'\xA3', b'\xC2')  # Ł -> c
                .replace(b'\xC6', b'\xC4')  # Ć -> d
                .replace(b'\xCA', b'\xC7')  # Ę -> f
                .replace(b'\x8C', b'\xC9')  # Ś -> g
                .replace(b'\xA5', b'\xCB')  # Ą -> h
                .replace(b'\x8F', b'\xD4')  # Ź -> i
                .replace(b'\xD1', b'\xD6')  # Ń -> j

            )
            temp_file.write(line)

        temp_file.close()
        txt_file.close()
        shutil.move(temp_path, txt_path)
        logger.info("Success! All chars replaced in " + txt_path)


def replace_chars_in_multiple_folders(tab_extensions: List[str], tab_folders: List[str]) -> None:
    for ext in tab_extensions:
        for fold in tab_folders:
            replace_chars_recursive_for_single_file_type(ext, fold)


if __name__ == '__main__':
    logger.info("Starting main...")

    replace_extensions: List[str] = json.loads(os.environ["REPLACE_EXTENSIONS"])  # e.g. ["txt"]
    replace_folders: List[str] = json.loads(os.environ["REPLACE_FOLDERS"])
    replace_chars_in_multiple_folders(replace_extensions, replace_folders)

    logger.info("Exiting main...")


