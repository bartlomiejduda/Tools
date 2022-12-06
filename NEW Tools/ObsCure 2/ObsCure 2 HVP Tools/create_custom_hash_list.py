"""
Copyright © 2022  Bartłomiej Duda
License: GPL-3.0 License
"""

# Program tested on Python 3.11

# Ver    Date        Author               Comment
# v0.1   06.12.2022  Bartlomiej Duda      -
from typing import List

from objects import HashEntryObject

custom_hash_list: List[HashEntryObject] = []

print("Starting to create custom hash list...")


clean_hash_file = open("hash_lists\obscure_2_hash_clean_list.txt", "rt")

# TODO