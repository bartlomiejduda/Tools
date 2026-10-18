"""
Copyright © 2026  Bartłomiej Duda
License: GPL-3.0 License
"""

import os
import glob
import shutil
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

        # https://www.ascii-code.com/CP1250
        for line in txt_file:
            line = (
                line

                # big chars
                .replace(b'\xAF', b'\xC1')  # Ż
                .replace(b'\xA3', b'\xC2')  # Ł
                .replace(b'\xC6', b'\xC4')  # Ć
                .replace(b'\xCA', b'\xC7')  # Ę
                .replace(b'\x8C', b'\xC9')  # Ś
                .replace(b'\xA5', b'\xCB')  # Ą
                .replace(b'\x8F', b'\xD4')  # Ź
                .replace(b'\xD1', b'\xD6')  # Ń

            )
            temp_file.write(line)

        temp_file.close()
        txt_file.close()
        shutil.move(temp_path, txt_path)
        logger.info("Success! All chars replaced in " + txt_path)


def replace_chars_in_multiple_folders(tab_extensions, tab_folders) -> None:
    for ext in tab_extensions:
        for fold in tab_folders:
            replace_chars_recursive_for_single_file_type(ext, fold)
