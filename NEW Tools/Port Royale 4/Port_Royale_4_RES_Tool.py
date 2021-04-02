# -*- coding: utf-8 -*-

'''
Copyright © 2021  Bartłomiej Duda
License: GPL-3.0 License 
'''


# Program tested on Python 3.7.0
# It should be used with Port Royale 4 (v1.5)

# Ver    Date        Author               Comment
# v0.1   02.04.2021  Bartlomiej Duda      -

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
    

def export_data(in_file_path, out_folder_path):
    '''
    Function for exporting data from RES files
    '''    
    bd_logger("Starting export_data...")  
    
    if not os.path.exists(os.path.dirname(out_folder_path)):  
        os.makedirs(os.path.dirname(out_folder_path))     
    
    res_file = open(in_file_path, 'rb')
    HEADER_SIZE = 33
    
    sign = ""
    try:
        sign = res_file.read(4).decode("utf8")
    except:
        pass
    
    if sign != "L10N":
        raise Exception("It is not a valid file from Port Royale 4!")
    
    res_file.read(25) # read header data 
    num_of_files = struct.unpack("<L", res_file.read(4))[0]
    res_file.read(4) # read unknown
    
    out_path = out_folder_path + "out_text.txt"
    out_file = open(out_path, "wt+")
    out_file.close()
    
    for i in range(num_of_files):
        str_offset = struct.unpack("<L", res_file.read(4))[0] + HEADER_SIZE
        str_len = struct.unpack("<L", res_file.read(4))[0]
        str_unknown = res_file.read(4)
        
        back_offset = res_file.tell()
        
        res_file.seek(str_offset)
        out_str = "TEXT" + str(i+1) + "=" + res_file.read(str_len).decode("utf16").rstrip("\x00")
        
        out_file = open(out_path, "at+", encoding="utf16")
        out_file.write(out_str + "\n")
        out_file.close()
    
        res_file.seek(back_offset)
    
    res_file.close()
    bd_logger("Ending export_data...")    
    
    
    
    
def main():
    '''
    Main function of this program. If you are planning to use it,
    you should adjust paths first.
    '''   
    main_switch = 1
    # 1 - data export 
    

    if main_switch == 1:
        p_in_file_path = "C:\\Users\\Arek\\Desktop\\global-new.res"
        p_out_folder_path = "C:\\Users\\Arek\\Desktop\\global-new.res_OUT\\"
        export_data(p_in_file_path, p_out_folder_path)
        
    else:
        bd_logger("Wrong option selected!")
        
        
    
    bd_logger("End of main...")    
    
    
    
main()