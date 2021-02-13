# -*- coding: utf-8 -*-

'''
Copyright © 2021  Bartłomiej Duda
License: GPL-3.0 License 
'''


# Program tested on Python 3.7.0
# It should be used with Hellpoint

# Ver    Date        Author               Comment
# v0.1   13.02.2021  Bartlomiej Duda      -

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
    mod_res = int(in_len % 4)
    if mod_res == 0:
        return mod_res
    else:
        res = 4 - mod_res
        return res


def export_data(in_file_path, out_folder_path):
    '''
    Function for exporting text from DAT files
    '''    
    bd_logger("Starting export_data...")  
    
    if not os.path.exists(out_folder_path):
        os.makedirs(out_folder_path)      
    
    dat_file = open(in_file_path, 'rb')
    out_file = open(out_folder_path + "out.txt", "wt+", encoding="utf8")
    
    
    dat_file.read(28) # unknown
    
    lang_len = struct.unpack("<L", dat_file.read(4))[0]
    dat_file.read(lang_len) # en
    
    padding_len = calculate_padding_len(lang_len)
    dat_file.read(padding_len)
    
    num_of_blocks = 3  # hardcoded for en.dat!
    
    for j in range(num_of_blocks):
    
        num_of_strings = struct.unpack("<L", dat_file.read(4))[0]
        
        for i in range(num_of_strings):
            str_len = struct.unpack("<L", dat_file.read(4))[0]
            out_text = dat_file.read(str_len).decode("utf8")
            out_file.write(out_text + "\n")
            #print(out_text)
            padding_len = calculate_padding_len(str_len)
            dat_file.read(padding_len)   
            
            
    
    
   
    out_file.close()
    dat_file.close()
    bd_logger("Ending export_data...")    
    
    
    
    
def main():
    '''
    Main function of this program. If you are planning to use it,
    you should adjust paths first.
    '''   
    main_switch = 1
    # 1 - data export 
    

    if main_switch == 1:
        p_in_file_path = "C:\\Users\\Arek\\Desktop\\en.dat"
        p_out_folder_path = "C:\\Users\\Arek\\Desktop\en.dat_OUT\\"
        export_data(p_in_file_path, p_out_folder_path)
        
    else:
        bd_logger("Wrong option selected!")
        
        
    
    bd_logger("End of main...")    
    
    
    
main()