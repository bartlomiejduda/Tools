# -*- coding: utf-8 -*-

# Tested on Python 3.8.0
# This tool should be used with Crazy Ball (PC)

# Ver    Date        Author
# v0.1   25.10.2020  Bartlomiej Duda

import os
import sys
import struct



def bd_logger(in_str):
    import datetime
    now = datetime.datetime.now()
    print(now.strftime("%d-%m-%Y %H:%M:%S") + " " + in_str)    
    

def export_data(in_file_path, out_folder_path):
    '''
    Function for exporting data from BOD files
    '''    
    bd_logger("Starting export_data...")  
    
    if not os.path.exists(out_folder_path):
        os.makedirs(out_folder_path)      
    
    bod_file = open(in_file_path, 'rb')
    
    bod_file.seek(64)
    num_of_files = struct.unpack("<L", bod_file.read(4))[0]
    
    for i in range(num_of_files):
        file_name = bod_file.read(256).decode("utf8").rstrip("\x00")
        file_offset = struct.unpack("<L", bod_file.read(4))[0]
        file_size = struct.unpack("<L", bod_file.read(4))[0]
        
        back_offset = bod_file.tell()
        bod_file.seek(file_offset)
        data = bod_file.read(file_size)
        
        out_file_path = ""
        out_file_folder_path = ""
        
        out_file_path = out_folder_path + file_name 
        print(out_file_path)
        out_file_folder_path = out_file_path.split("\\")[0:-1]
        out_file_folder_path = "\\".join(out_file_folder_path)
        
        if not os.path.exists(out_file_folder_path):
            os.makedirs(out_file_folder_path) 
            
        out_file = open(out_file_path, "wb+")
        out_file.write(data)
        out_file.close()

        
        bod_file.seek(back_offset)
   
    
    bod_file.close()
    bd_logger("Ending export_data...")    
    
    
    
    
def main():
    
    main_switch = 1
    # 1 - data export 
    

    if main_switch == 1:
        p_in_file_path = "C:\\Program Files (x86)\\Crazy Ball\\cb.bod"
        p_out_folder_path = "C:\\Users\\Arek\\Desktop\\cb.bod_OUT\\"
        export_data(p_in_file_path, p_out_folder_path)
        
    else:
        print("Wrong option selected!")
        
        
    
    bd_logger("End of main...")    
    
    
    
main()