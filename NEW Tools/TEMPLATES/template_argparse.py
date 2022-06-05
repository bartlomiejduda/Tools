"""
Copyright © 2022  Bartłomiej Duda
License: GPL-3.0 License
"""

# Program tested on Python 3.10.4

# Ver    Date        Author               Comment
# v0.1   28.05.2022  Bartlomiej Duda      -



import os
import sys
import argparse
from typing import Optional
from logger import get_logger

logger = get_logger(__name__)

VERSION_NUM = "v0.1"
EXE_FILE_NAME = f"some_game_text_tool_{VERSION_NUM}.exe"
PROGRAM_NAME = f'Some Game Text Tool {VERSION_NUM}'

def check_file(in_file_path, create_dirs=False):
    if not os.path.isfile(in_file_path):
        return "NOT_FILE_ERROR", "This is not a valid input file path!"

    in_file_extension = in_file_path.split(".")[-1]
    if in_file_extension.upper() != "XML":
        return "NOT_XML_ERROR", f"{in_file_path} is not a valid XML file!"

    if create_dirs:
        if not os.path.exists(os.path.dirname(in_file_path)):
            try:
                os.makedirs(os.path.dirname(in_file_path))
            except FileNotFoundError:
                return "CANT_CREATE_DIR_ERROR", "Can't create output directory!"



def check_directory(in_directory):
    pass # TODO


def export_data(in_file_path: str, out_file_path: str) -> Optional[tuple]:
    """
    Function for exporting data from XML files
    """
    logger.info("Starting export_data...")

    code, status = check_file(in_file_path)
    if code != "OK":
        return code, status

    code, status = check_file(out_file_path)
    if code != "OK":
        return code, status

    xml_file = open(in_file_path, 'rt', encoding="utf8")
    ini_file = open(out_file_path, 'wt', encoding="utf8")



    ini_file.close()
    xml_file.close()
    logger.info(f'File {out_file_path} has been saved.')
    logger.info("Ending export_data...")
    return "OK", ""


def import_data(xml_file_path: str, ini_file_path: str, new_xml_file_path) -> Optional[tuple]:
    """
    Function for importing data to XML files
    """
    logger.info("Starting import_data...")



    xml_file = open(xml_file_path, 'rt', encoding="utf8")
    ini_file = open(ini_file_path, 'rt', encoding="utf8")
    new_xml_file = open(new_xml_file_path, 'wt', encoding="utf8")


    logger.info("Ending import_data...")
    return "OK", ""


def main():
    """
    Main function of this program.
    """
    parser = argparse.ArgumentParser(prog=EXE_FILE_NAME,
                                     description=PROGRAM_NAME)
    parser.add_argument('-e', '--ext', metavar=('<xml_file_path>', '<ini_file_path>'),
                        type=str, nargs=2, required=False, help='Extract data (convert XML to INI)')
    parser.add_argument('-i', '--imp', metavar=('<xml_file_path>', '<ini_file_path>', '<new_xml_path>'),
                        type=str, nargs=3, required=False, help='Import data (convert INI to XML)')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    if args.ext is not None:
        code, status = export_data(args.ext[0], args.ext[1])
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
