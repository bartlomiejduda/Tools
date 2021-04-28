# -*- coding: utf-8 -*-

"""
Copyright © 2021  Bartłomiej Duda
License: GPL-3.0 License 
"""


# Program tested on Python 3.7.0
# It should be used with King of Colosseum II (PS2)

# Ver    Date        Author               Comment
# v0.1   28.04.2021  Bartlomiej Duda      -

import os
import sys
import struct
import datetime


def bd_logger(in_str):
    '''
    Function for logging debug messages
    '''   
    now = datetime.datetime.now()
    print(now.strftime("%d-%m-%Y %H:%M:%S") + " " + in_str)    

def calculate_padding_len(in_len):
    div = 2048
    padding_val = (div - (in_len % div)) % div
    return padding_val  
    

def export_data(in_file_path, out_folder_path):
    '''
    Function for exporting data from 000, 001 files
    '''    
    bd_logger("Starting export_data...")  
    
    if not os.path.exists(os.path.dirname(out_folder_path)):  
        os.makedirs(os.path.dirname(out_folder_path))     
    
    bin_file = open(in_file_path, 'rb')
    
    bin_file.read(4) # signature 
    num_of_files = struct.unpack("<l", bin_file.read(4))[0]
    
    
    header_and_info_array_size = 8 + num_of_files * 16
    padd_len = calculate_padding_len( header_and_info_array_size )
    base_offset = header_and_info_array_size + padd_len
    
    for i in range(num_of_files):
        f_offset = base_offset + struct.unpack("<l", bin_file.read(4))[0]
        block_size = struct.unpack("<l", bin_file.read(4))[0]
        f_uncomp_size = struct.unpack("<l", bin_file.read(4))[0]
        flag1 = struct.unpack("<h", bin_file.read(2))[0]
        comp_flag = struct.unpack("<h", bin_file.read(2))[0]
        back_offset = bin_file.tell()
        f_ext = ""
        
        
        bin_file.seek(f_offset)
        
        try:
            sign = bin_file.read(4).decode("utf8")
            if sign == "IECS":
                f_ext = ".hd"  # PS2 HD Audio 
            elif sign == "TIM2":
                f_ext = ".tim2" # PS2 TIM2 Image 
            elif "//" in sign:
                f_ext = ".txt" # some text file 
        except:
            pass
        finally:
            bin_file.seek(f_offset)
        
        
        if comp_flag == 0:
            f_data = bin_file.read(f_uncomp_size)
            if f_ext == "":
                f_ext = ".bin"
        else:
            f_data = bin_file.read(block_size)
            if f_ext == "":
                f_ext = ".comp"
        
        
        f_name = "file" + str(i+1) + f_ext
        f_path = out_folder_path + f_name
        print(f_path)
        
        out_file = open(f_path, "wb+")
        out_file.write(f_data)
        out_file.close()
        
            
        bin_file.seek(back_offset)

    bin_file.close()
    bd_logger("Ending export_data...")    
    
    
    
    
def main():
    '''
    Main function of this program. If you are planning to use it,
    you should adjust paths first.
    '''   
    main_switch = 1
    # 1 - data export 
    

    if main_switch == 1:
        p_in_file_path = "C:\\Users\\Arek\\Desktop\\kc2fire.000"
        p_out_folder_path = "C:\\Users\\Arek\\Desktop\\kc2fire.000_OUT\\"
        export_data(p_in_file_path, p_out_folder_path)
        
    else:
        bd_logger("Wrong option selected!")
        
        
    
    bd_logger("End of main...")    
    
    
    
main()