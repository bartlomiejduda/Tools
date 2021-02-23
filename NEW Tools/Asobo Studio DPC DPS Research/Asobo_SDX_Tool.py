# -*- coding: utf-8 -*-

'''
Copyright © 2021  Bartłomiej Duda
License: GPL-3.0 License 
'''


# Program tested on Python 3.7.0
# It should be used with WALL-E (PC)

# Ver    Date        Author               Comment
# v0.1   24.02.2021  Bartlomiej Duda      -

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
    Function for exporting data from SDX files
    '''    
    bd_logger("Starting export_data...")  
    
    if not os.path.exists(out_folder_path):
        os.makedirs(out_folder_path)      
    
    sdx_file = open(in_file_path, 'rb')
    
    magic = struct.unpack("4s", sdx_file.read(4))[0]
    
    if magic not in (b'\xeb\x03\x00\x00'):
        bd_logger("It is not a valid Asobo SDX file from Wall-E! Aborting!")
        return
    
    num_of_entries = struct.unpack("<L", sdx_file.read(4))[0]
    
    sdx_file.read(8) # ID / description / nulls
    
    for i in range(num_of_entries):
        unknown1 = struct.unpack("<H", sdx_file.read(2))[0]
        sample_freq = struct.unpack("<H", sdx_file.read(2))[0]
        sample_rate = struct.unpack("<H", sdx_file.read(2))[0]
        header_size = struct.unpack("<H", sdx_file.read(2))[0]
        sample_offset = struct.unpack("<L", sdx_file.read(4))[0]
        sample_size = struct.unpack("<L", sdx_file.read(4))[0]
        
        file_name = "audio_file" + str(i+1) + ".bin"
        back_offset = sdx_file.tell()
        

        out_file_path = out_folder_path + file_name
        print(out_file_path)
        
        
        sdx_file.seek(sample_offset)
        file_data = sdx_file.read(sample_size)
        
        out_file = open(out_file_path, "wb+")
        out_file.write(file_data)
        out_file.close()
        
        
        sdx_file.seek(back_offset)
    
    
   
    
    sdx_file.close()
    bd_logger("Ending export_data...")    
    
    
    
    
def main():
    '''
    Main function of this program. If you are planning to use it,
    you should adjust paths first.
    '''   
    main_switch = 1
    # 1 - data export 
    

    if main_switch == 1:
        p_in_file_path = "C:\\Users\\Arek\\Desktop\\01.SDX"
        p_out_folder_path = "C:\\Users\\Arek\\Desktop\\01.SDX_OUT\\"
        export_data(p_in_file_path, p_out_folder_path)
        
    else:
        bd_logger("Wrong option selected!")
        
        
    
    bd_logger("End of main...")    
    
    
    
main()