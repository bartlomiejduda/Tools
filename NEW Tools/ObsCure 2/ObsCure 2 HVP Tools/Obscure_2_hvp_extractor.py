"""
Copyright © 2022  Bartłomiej Duda
License: GPL-3.0 License
"""

# Program tested on Python 3.11

# Ver    Date        Author               Comment
# v0.1   04.12.2022  Bartlomiej Duda      -


from reversebox.io_files.file_handler import FileHandler
print("Starting HVP extract script...")


hvp_path = "C:\\Users\\Lenovo\\Desktop\\Obscure_2_RESEARCH\\cachpack.hvp"
hvp_handler = FileHandler(hvp_path, "rb")

hvp_handler.open()


# read header
signature = hvp_handler.read_uint32()
if signature != 262144:
    print("It is not valid HVP file!")
    exit(0)
zero = hvp_handler.read_uint32()
number_of_entries = hvp_handler.read_uint32()
directory_crc32 = hvp_handler.read_uint32()


# read directory
for i in range(number_of_entries):
    crc_hash = hvp_handler.read_uint32()
    # TODO



print("Export script finished!")  # TODO - replace with logging