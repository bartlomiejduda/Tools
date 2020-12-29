# -*- coding: utf-8 -*-

'''
Copyright © 2020  Bartłomiej Duda
License: GPL-3.0 License 
'''


# Program tested on Python 3.7.0
# It should be used with PGA Tour 97 (PS1)

# Ver    Date        Author               Comment
# v0.1   29.12.2020  Bartlomiej Duda      -

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


def get_name(in_file):
    out_name = ""
    while 1:
        ch = struct.unpack("c", in_file.read(1))[0]

        if ord(ch) != 0:
            out_name += ch.decode("utf8")
        else:
            break
    return out_name



def export_data(in_file_path, out_folder_path):
    '''
    Function for exporting data from BIG/VIV files
    '''    
    bd_logger("Starting export_data...")  
    
    if not os.path.exists(out_folder_path):
        os.makedirs(out_folder_path)      
    
    big_file = open(in_file_path, 'rb')
    
    big_file.read(4) # magic 
    big_file.read(4) # archive size
    num_of_files = struct.unpack(">L", big_file.read(4))[0]
    big_file.read(4) # first file offset
    
    
    for i in range(num_of_files):
        file_offset = struct.unpack(">L", big_file.read(4))[0]
        file_size = struct.unpack(">L", big_file.read(4))[0]
        file_name = get_name(big_file)

        
        back_offset = big_file.tell()
        big_file.seek(file_offset)
        file_data = big_file.read(file_size) 
        
        out_file_path = out_folder_path + file_name
        print(out_file_path)
        out_file = open(out_file_path, "wb+")
        out_file.write(file_data)
        out_file.close()
    
        big_file.seek(back_offset)
    
    
   
    
    big_file.close()
    bd_logger("Ending export_data...")    
    
    
    
    
def main():
    '''
    Main function of this program. If you are planning to use it,
    you should adjust paths first.
    '''   
    main_switch = 2
    # 1 - data export 
    # 2 - data export from ALL viv files (with fixed output folder)
    

    if main_switch == 1:
        p_in_file_path = "C:\\Users\Arek\\Desktop\\PGA TOUR\\ISO_OUT\\RESIDENT.VIV"
        p_out_folder_path = "C:\\Users\Arek\\Desktop\\PGA TOUR\\ISO_OUT\\RESIDENT.VIV_OUT\\"
        export_data(p_in_file_path, p_out_folder_path)
       
    elif main_switch == 2:
        
        p_in_folder_path = "C:\\Users\Arek\\Desktop\\PGA TOUR\\ISO_OUT\\"
        p_out_folder_path = "C:\\Users\Arek\\Desktop\\PGA TOUR\\ISO_OUT\\ALL_VIV_FILES_OUT\\"
        
        for root, dirs, files in os.walk(p_in_folder_path):
            for file in files:
                if file.endswith('.VIV'):
                    p_in_file_path = os.path.join(root, file) 
                    export_data(p_in_file_path, p_out_folder_path)
       
        
    else:
        print("Wrong option selected!")
        
        
    
    bd_logger("End of main...")    
    
    
    
main()