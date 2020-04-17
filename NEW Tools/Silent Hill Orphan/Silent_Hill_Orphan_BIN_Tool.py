# -*- coding: utf-8 -*-

# Tested on Python 3.8.0
# This tool should be used with Silent Hill: Orphan (Java)

# Ver    Date        Author
# v0.1   17.04.2020  Bartlomiej Duda




VERSION_NUM = "v0.1"

import os
import sys
import struct



def bd_logger(in_str):
    import datetime
    now = datetime.datetime.now()
    print(now.strftime("%d-%m-%Y %H:%M:%S") + " " + in_str)    
    


def export_bin(in_BIN_filepath, out_folder_path):
    '''
    Function for exporting data from BIN files
    '''    
    bd_logger("Starting export_bin...")    
    
    bin_file = open(in_BIN_filepath, 'rb')
    
    num_of_chunks = struct.unpack('b', bin_file.read(1))[0]
    print("num_of_chunks: " + str(num_of_chunks) )
    
    
    #read chunks
    for i in range(num_of_chunks):
        chunk_name_length = struct.unpack('>b', bin_file.read(1))[0]
        chunk_name = bin_file.read(chunk_name_length).decode("utf8")
        print( str(i+1) + ") chunk_name: " + chunk_name)
        data_size = struct.unpack('>h', bin_file.read(2))[0]
        
        if data_size == 0:
            continue
        else:
            data = bin_file.read(data_size)
            print("out: " + out_folder_path + "\\" + chunk_name.replace("/", "\\") )

    
   
    
    bin_file.close()
    bd_logger("Ending export_bin...")    
    
    
    
    
def main():
    
    main_switch = 1
    # 1 - bin export 
    
    
    if main_switch == 1:
        p_in_BIN_filepath = "C:\\Users\\Arek\\Desktop\\Silent_Hill_Orphan_SPOL\\JAR_out\\chunks\\0.bin"
        p_out_folder_path = "C:\\Users\\Arek\\Desktop\\Silent_Hill_Orphan_SPOL\\JAR_out\\chunks\\0.bin_out"
        export_bin(p_in_BIN_filepath, p_out_folder_path)
        
    
    bd_logger("End of main...")    
    
    
    
main()