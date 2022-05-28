"""
Copyright © 2022  Bartłomiej Duda
License: GPL-3.0 License
"""

# Program tested on Python 3.10.4

# Ver    Date        Author               Comment
# v0.1   28.05.2022  Bartlomiej Duda      -


# This program is for ...

import os
import sys
import argparse
from typing import Optional
import xmltodict
from logger import get_logger

logger = get_logger(__name__)


def export_data(in_file_path: str, out_file_path: str) -> Optional[tuple]:
    """
    Function for exporting data from XML files
    """
    logger.info("Starting export_data...")

    if not os.path.isfile(in_file_path):
        return "NOT_FILE_ERROR", "This is not a valid input file path!"

    in_file_extension = in_file_path.split(".")[-1]
    if in_file_extension.upper() != "XML":
        return "NOT_XML_ERROR", f"{in_file_path} is not a valid XML file!"

    if not os.path.exists(os.path.dirname(out_file_path)):
        try:
            os.makedirs(os.path.dirname(out_file_path))
        except FileNotFoundError:
            return "CANT_CREATE_DIR_ERROR", "Can't create output directory!"

    out_file_extension = out_file_path.split(".")[-1]
    if out_file_extension.upper() != "INI":
        return "NOT_INI_ERROR", f"{out_file_path} is not a valid INI file!"

    xml_file = open(in_file_path, 'rt', encoding="utf8")
    ini_file = open(out_file_path, 'wt', encoding="utf8")

    xml_data = xml_file.read()
    xml_dict = xmltodict.parse(xml_data)

   

    ini_file.close()
    xml_file.close()
    logger.info("Ending export_data...")
    return "OK", ""


def import_data(in_file_path: str, out_folder_path: str) -> Optional[tuple]:
    return "IMPORT_NOT_SUPPORTED", "Import is not supported yet!"


def main():
    """
    Main function of this program.
    """
    parser = argparse.ArgumentParser(prog="satellite_reign_text_tool.exe", description='TEMPLATE Tool v1.0')
    parser.add_argument('-e', '--ext', type=str, nargs="+", required=False, help='Extract data')
    parser.add_argument('-i', '--imp', type=str, nargs="+", required=False, help='Import data')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    if args.ext is not None:
        export_result = export_data(args.ext[0], args.ext[1])
        if export_result[0] != "OK":
            logger.error(f"{export_result[0]}: {export_result[1]}")
            sys.exit(-1)
    elif args.imp is not None:
        import_result = import_data(args.imp[0], args.imp[1])
        if import_result[0] != "OK":
            logger.error(f"{import_result[0]}: {import_result[1]}")
            sys.exit(-2)

    logger.info("End of main... Program has been executed successfully.")
    sys.exit(0)


if __name__ == "__main__":
    main()
