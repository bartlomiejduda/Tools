# Tested on Python 3.11
# This tool should be used with Giana's Return
# You need "ReverseBox" package to use this tool

# Ver    Date        Author             Comment
# v0.1   26.11.2020  Bartlomiej Duda    Initial version
# v0.2   28.11.2020  Bartlomiej Duda    Added decryption method
# v0.3   15.04.2023  Bartlomiej Duda    Add ReverseBox integration

import os
import struct
import zlib
from reversebox.encryption.encryption_xor_gianas_return_zda import xor_zda_decrypt_data
from reversebox.common.logger import get_logger

logger = get_logger(__name__)


def export_data(in_file_path, out_folder_path):
    """
    Function for exporting data from ZDA files
    """
    logger.info("Starting export_data...")
    
    if not os.path.exists(out_folder_path):
        os.makedirs(out_folder_path)      
    
    zda_file = open(in_file_path, 'rb')
    
    zda_file.read(4)
    num_of_files = struct.unpack("<L", zda_file.read(4))[0]
    zda_file.read(4)
    
    name_arr = []
    size_arr = []
    for i in range(num_of_files):
        f_name = zda_file.read(40).decode("utf-8").rstrip("\x00")
        f_uncomp_size = zda_file.read(4)
        f_comp_size = struct.unpack("<L", zda_file.read(4))[0]
        f_offset = zda_file.read(4)
        
        name_arr.append(f_name)
        size_arr.append(f_comp_size)
        
    for i in range(num_of_files):
        f_data = zlib.decompress(zda_file.read(size_arr[i]))  # data decompression
        f_name = name_arr[i]
        f_path = out_folder_path + f_name
        f_data = xor_zda_decrypt_data(f_data) # data decryption
        print(f_path)
        
        out_file = open(f_path, "wb+")
        out_file.write(f_data)
        out_file.close()

    zda_file.close()
    logger.info("Ending export_data...")
    

def main():
    
    main_switch = 1
    # 1 - data export 
    # 2 - data export (all archives)

    if main_switch == 1:
        logger.info("Option 1 start")
        p_in_file_path = "C:\\Users\\User\\Desktop\\data\\music0.zda"
        p_out_folder_path = "C:\\Users\\User\\Desktop\\data\\music0.zda_OUT\\"
        export_data(p_in_file_path, p_out_folder_path)
        
    elif main_switch == 2:
        logger.info("Option 2 start")
        p_data_dir_path = "C:\\Users\\User\\Desktop\\data\\"
        
        for root, dirs, files in os.walk(p_data_dir_path):
            for file in files:
                if file.endswith(".zda"):
                    in_archive = os.path.join(root, file)
                    out_folder = in_archive + "_OUT\\"
                    export_data(in_archive, out_folder)
        
    else:
        print("Wrong option selected!")

    logger.info("End of main...")


if __name__ == "__main__":
    main()
