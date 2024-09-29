"""
Copyright © 2024  Bartłomiej Duda
License: GPL-3.0 License
"""

from rarfile import RarFile


def main():
    passwords_list = []
    with open("passwords_list.txt", "rt") as passwords_list_file:
        for line in passwords_list_file:
            passwords_list.append(line.rstrip())

    with RarFile('test.rar', 'r') as myrar:
        for password in passwords_list:
            try:
                myrar.testrar(pwd=password)
                rar_namelist = myrar.namelist()
                if len(rar_namelist) > 0:
                    print(f"PASSWORD FOUND --> {password}")
                    break
                else:
                    raise Exception("Test failed!")
            except Exception as error:
                print(f"password not valid --> {password}")
    print("End of main")


if __name__ == '__main__':
    main()
