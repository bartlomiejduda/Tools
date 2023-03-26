"""
Copyright © 2021-2023  Bartłomiej Duda
License: GPL-3.0 License
"""

# Program tested on Python 3.11
# It should be used with Dink Smallwood HD (PC)

# Ver    Date        Author               Comment
# v0.1   27.05.2021  Bartlomiej Duda      -
# v0.2   22.01.2023  Bartlomiej Duda      -

import os
import datetime
import re


# constants
EXPORT_ENCODING = "utf8"
IMPORT_INPUT_ENCODING = "utf8"
IMPORT_ENCODING = "windows-1252"
REPLACE_REGEX = r'(\")(.*?)(\")'


def bd_logger(in_str):
    """
    Function for logging debug messages
    """
    now = datetime.datetime.now()
    print(now.strftime("%d-%m-%Y %H:%M:%S") + " " + in_str)


def export_text(list_of_file_paths, out_file_path):
    """
    Function for exporting text from C files
    """
    bd_logger("Starting export_text...")

    if not os.path.exists(os.path.dirname(out_file_path)):
        os.makedirs(os.path.dirname(out_file_path))

    out_file = open(out_file_path, "wt+", encoding=EXPORT_ENCODING)

    for in_file_path in list_of_file_paths:

        c_file = open(in_file_path, 'rt')
        c_file_name = os.path.basename(in_file_path)[0:-2]

        bd_logger("Processing file " + str(c_file_name) + "...")

        line_count: int = 0
        match_count: int = 0
        for line in c_file:
            line_count += 1
            line_matches = re.findall(REPLACE_REGEX, line)  # finds all strings in line

            for match in line_matches:  # sometimes there are multiple strings in one line
                match_count += 1
                out_str = c_file_name + "_" + str(line_count) + "_" + str(match_count) + "=" + str(match[1])
                out_file.write(out_str + "\n")

        c_file.close()

    out_file.close()
    bd_logger("Ending export_text...")


def char_replacer(input_text: str) -> str:
    """
    This function is used to replace polish characters in all text files
    """
    return (input_text.replace("Ż", "\xC0")
                      .replace("Ó", "Ó")
                      .replace("Ł", "\xD2")
                      .replace("Ć", "\xD6")
                      .replace("Ę", "\xC9")
                      .replace("Ś", "\xC1")
                      .replace("Ą", "\xC2")
                      .replace("Ź", "\xC4")
                      .replace("Ń", "\xD1")

                      .replace("ż", "\xE0")
                      .replace("ó", "ó")
                      .replace("ł", "\xF2")
                      .replace("ć", "\xF6")
                      .replace("ę", "\xE9")
                      .replace("ś", "\xE1")
                      .replace("ą", "\xE2")
                      .replace("ź", "\xE4")
                      .replace("ń", "\xF1")
            )


def import_text(in_file_path, list_of_file_paths):
    """
    Function for importing text to C files
    """
    bd_logger("Starting import_text...")

    in_script_file = open(in_file_path, "rt", encoding=IMPORT_INPUT_ENCODING)

    list_of_line_data = []
    for line in in_script_file:  # read data from translated script file
        l_text = line.split("=")[-1].split("\n")[0]
        l_name = line.split("=")[0].split("_")[0]
        l_linenum = line.split("=")[0].split("_")[1]

        line_data = (l_name, l_linenum, l_text)
        list_of_line_data.append(line_data)

    in_script_file.close()

    for f_path in list_of_file_paths:

        c_file_name = os.path.basename(f_path)[0:-2]
        print("Processing " + c_file_name + "...")

        r_file = open(f_path, "rt")
        out_file = open(f_path + "_temp", "wt+", encoding=IMPORT_ENCODING)

        curr_line = 0
        for line in r_file:
            curr_line += 1
            new_line = None
            for l_data in list_of_line_data:
                l_name = l_data[0]
                l_linenum = int(l_data[1])
                l_text = l_data[2].split("\n")[0]
                l_text = char_replacer(l_text)

                if l_name == c_file_name and l_linenum == curr_line:
                    try:
                        new_line = re.sub(REPLACE_REGEX, "\"" + l_text + "\"", line)
                    except Exception as error:
                        print(f"ERROR occurred: {error} for line {line} in file {c_file_name}")

            if new_line is None:
                new_line = line

            try:
                out_file.write(new_line)
            except Exception as error:
                print(f"Error occurred: {error}")
                raise

        r_file.close()
        out_file.close()

        os.replace(f_path + "_temp", f_path)

    bd_logger("Ending import_text...")


def main():
    """
    Main function of this program. If you are planning to use it,
    you should adjust paths first.
    """
    main_switch = 2
    # 1 - text export 
    # 2 - text import

    p_c_files_directory = "C:\\Users\\User\\Desktop\\DINK_C_FILES"
    p_script_file_path = "C:\\Users\\User\\Desktop\\out_script.ini"
    p_files_paths = [os.path.join(p_c_files_directory, f) for f in os.listdir(p_c_files_directory) if f[-2:] == '.c']

    if main_switch == 1:
        export_text(p_files_paths, p_script_file_path)

    elif main_switch == 2:
        import_text(p_script_file_path, p_files_paths)

    else:
        bd_logger("Wrong option selected!")

    bd_logger("End of main...")


if __name__ == "__main__":
    main()
