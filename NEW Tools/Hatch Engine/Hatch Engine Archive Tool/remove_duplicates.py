"""
Copyright © 2025  Bartłomiej Duda
License: GPL-3.0 License
"""
import os


# Script for removing duplicates from filenames list

def remove_duplicates_in_txt_file(input_file_path: str, output_file_path: str) -> bool:

    filenames_list: list = []
    input_file = open(input_file_path, "rt")
    output_file = open(output_file_path, "wt")

    for line in input_file:
        line = line.strip()

        if line not in filenames_list:
            filenames_list.append(line)
            print(line)

    for filename in filenames_list:
        output_file.write(filename + "\n")

    input_file.close()
    output_file.close()
    return True


def main():
    input_txt_path: str = os.environ['INPUT_TXT_PATH']
    output_txt_path: str = os.environ['OUTPUT_TXT_PATH']
    remove_duplicates_in_txt_file(input_txt_path, output_txt_path)


if __name__ == "__main__":
    main()
