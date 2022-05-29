"""
Copyright © 2022  Bartłomiej Duda
License: GPL-3.0 License
"""

# Program tested on Python 3.10.4

# Ver    Date        Author               Comment
# v0.1   28.05.2022  Bartlomiej Duda      -
# v0.2   29.05.2022  Bartlomiej Duda      -


# This program is for converting XML localization file
# from game "Sattelite Reign" to INI file

import os
import sys
import argparse
from typing import Optional
import xmltodict
from logger import get_logger

logger = get_logger(__name__)

VERSION_NUM = "v0.2"
EXE_FILE_NAME = "satellite_reign_text_tool_" + VERSION_NUM + ".exe"
PROGRAM_NAME = f'Satellite Reign Text Tool {VERSION_NUM}'


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

    translation_rows = xml_dict.get("Sheets").get("sheet").get("row")

    for translation_row in translation_rows:
        row_name = translation_row.get('@name')
        for translation_column in translation_row.get("col"):
            column_name = translation_column.get('@name')
            if column_name not in ('id', 'cz', 'fr', 'ge', 'it', 'ru', 'sp'):
                translation_text = translation_column.get('#text')
                if translation_text:
                    translation_entry = row_name + "_###_" + column_name + "_###_" + "=" + \
                                        translation_text.replace("\n", "\\n") + "\n"
                    ini_file.write(translation_entry)

    ini_file.close()
    xml_file.close()
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

    # old XML parsing
    xml_data = xml_file.read()
    xml_dict = xmltodict.parse(xml_data)

    # INI parsing
    line_number = 0
    ini_array = []
    for line in ini_file:
        line_number += 1
        line_dict = {}
        line_dict['line_number'] = line_number
        line_dict['row_name'] = line.split('_###_')[0]
        line_dict['column_name'] = line.split('_###_')[1]
        line_dict['line_text'] = line.split('=')[-1]
        ini_array.append(line_dict)


    # xml_dict = None
    # xml_out_data = xmltodict.unparse(xml_dict, pretty=True)
    # xml_file_out = open("C:\\Users\\Lenovo\\Desktop\\out.xml", 'wt', encoding="utf8")
    # xml_file_out.write(xml_out_data)
    # xml_file_out.close()
    # logger.info("Ending import_data...")
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
        export_result = export_data(args.ext[0], args.ext[1])
        if export_result[0] != "OK":
            logger.error(f"{export_result[0]}: {export_result[1]}")
            sys.exit(-1)
    elif args.imp is not None:
        import_result = import_data(args.imp[0], args.imp[1], args.imp[2])
        if import_result[0] != "OK":
            logger.error(f"{import_result[0]}: {import_result[1]}")
            sys.exit(-2)

    logger.info("End of main... Program has been executed successfully!")
    sys.exit(0)


if __name__ == "__main__":
    main()
