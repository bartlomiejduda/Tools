# -*- coding: utf-8 -*-

'''
Copyright © 2021  Bartłomiej Duda
License: GPL-3.0 License 
'''


# Program tested on Python 3.7.0
# It should be used with Drakan

# Ver    Date        Author               Comment
# v0.1   13.01.2021  Bartlomiej Duda      -

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
    

from itertools import cycle
def xore(data, key):
    return bytes(a ^ b for a, b in zip(data, cycle(key)))
    
    
def decrypt_data(in_data_str, in_data_len):
    '''
    Function for decrypting text files
    '''      
    key = 0x5FDD390D
    
    out_data = b''
    for i in range(in_data_len):
        out_data += xore(struct.pack("B", in_data_str[i]) , struct.pack("B", key & 0xFF))
        key = (key<<3) | (key>>(32-3))
        
    return out_data
    
    

def export_data(in_file_path, out_folder_path):
    '''
    Function for exporting data from RRC files
    '''    
    bd_logger("Starting export_data...")  
    
    if not os.path.exists(out_folder_path):
        os.makedirs(out_folder_path)      
    
    rrc_file = open(in_file_path, 'rb')
    
    magic = struct.unpack("4s", rrc_file.read(4))[0].decode("utf8")
    
    if magic != "SRSC":
        bd_logger("This is not valid RRC file! Exiting...")
        return
    
    rrc_file.read(2) # version 
    
    dir_offset = struct.unpack("<L", rrc_file.read(4))[0]
    num_of_files = struct.unpack("<H", rrc_file.read(2))[0]
    
    rrc_file.seek(dir_offset)
    
    for i in range(num_of_files):
        file_type = struct.unpack("<H", rrc_file.read(2))[0]
        rrc_file.read(2) # file_id
        rrc_file.read(2) # group_id
        file_offset = struct.unpack("<L", rrc_file.read(4))[0]
        file_size = struct.unpack("<L", rrc_file.read(4))[0]
        
        back_offset = rrc_file.tell()
        
        rrc_file.seek(file_offset)
        file_data = rrc_file.read(file_size)
        
        file_name = ""
        
        if file_type == 1025: # plain text 
            file_name = "file" + str(i+1) + ".txt"
            
        elif file_type == 1024: # encrypted text
            file_data = decrypt_data(file_data, len(file_data))
            file_name = "file" + str(i+1) + "_DECRYPTED.txt"
        else:
            file_name = "file" + str(i+1) + ".bin"
            
            
        out_file_path = out_folder_path + file_name
        out_file = open(out_file_path, "wb+")
        out_file.write(file_data)
        out_file.close()
        print(out_file_path)
        
        rrc_file.seek(back_offset)
   
    
    rrc_file.close()
    bd_logger("Ending export_data...")    
    
    
    
    
def main():
    '''
    Main function of this program. If you are planning to use it,
    you should adjust paths first.
    '''   
    main_switch = 1
    # 1 - data export 
    

    if main_switch == 1:
        p_in_file_path = "C:\\Users\\Arek\\Desktop\\DRAKAN\\Dragon.rrc"
        p_out_folder_path = "C:\\Users\\Arek\\Desktop\\DRAKAN\\Dragon.rrc_OUT\\"
        export_data(p_in_file_path, p_out_folder_path)
        
    else:
        print("Wrong option selected!")
        
        
    
    bd_logger("End of main...")    
    
    
    
main()