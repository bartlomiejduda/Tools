# -*- coding: utf-8 -*-

'''
Copyright © 2021  Bartłomiej Duda
License: GPL-3.0 License 
'''


# Program tested on Python 3.7.0
# It should be used with Raiders Sphere

# Ver    Date        Author               Comment
# v0.1   13.03.2021  Bartlomiej Duda      -

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
    Function for exporting data from PAC files
    '''    
    bd_logger("Starting export_data...")  
    
    if not os.path.exists(out_folder_path):
        os.makedirs(out_folder_path)      
    
    pac_file = open(in_file_path, 'rb')
    
    num_of_entries = struct.unpack("<L", pac_file.read(4))[0]
    
    for i in range(num_of_entries):
        path_len = struct.unpack("<L", pac_file.read(4))[0]
        file_path = pac_file.read(path_len).decode("utf8").rstrip("\x00")
        pac_file.read(8) # nulls 
        file_offset = struct.unpack("<L", pac_file.read(4))[0]
        comp_file_size = struct.unpack("<L", pac_file.read(4))[0]
        uncomp_file_size = struct.unpack("<L", pac_file.read(4))[0]
        

        out_path = out_folder_path + file_path
        out_folder = "\\".join(out_path.split("\\")[0:-1]) + "\\"
        
        if not os.path.exists(out_folder):
            os.makedirs(out_folder)   
        
        
        back_offset = pac_file.tell()
        pac_file.seek(file_offset)
        file_data = pac_file.read(comp_file_size)
        pac_file.seek(back_offset)
        
            
        print(out_path)
        out_file = open(out_path, "wb+")
        out_file.write(file_data)
        out_file.close()
        
    
   
    
    pac_file.close()
    bd_logger("Ending export_data...")    
    
    
    
    
def main():
    '''
    Main function of this program. If you are planning to use it,
    you should adjust paths first.
    '''   
    main_switch = 1
    # 1 - data export 
    

    if main_switch == 1:
        p_in_file_path = "C:\\Users\\Arek\\Desktop\\SpeSystem.pac"
        p_out_folder_path = "C:\\Users\\Arek\\Desktop\\SpeSystem.pac_OUT\\"
        export_data(p_in_file_path, p_out_folder_path)
        
    else:
        bd_logger("Wrong option selected!")
        
        
    
    bd_logger("End of main...")    
    
    
    
main()