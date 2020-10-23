# -*- coding: utf-8 -*-

# Tested on Python 3.8.0
# This tool should be used with Tony Hawk’s Underground (PS2)

# Ver    Date        Author
# v0.1   23.10.2020  Bartlomiej Duda

import os
import sys
import struct



def bd_logger(in_str):
    import datetime
    now = datetime.datetime.now()
    print(now.strftime("%d-%m-%Y %H:%M:%S") + " " + in_str) 
    
def get_bytes(in_val, in_mod):
    while 1:
        res = in_val % in_mod
        if res == 0:
            return in_val
        else:
            in_val += 1
    
def export_data(in_file_path, out_folder_path):
    '''
    Function for exporting data from HED/WAD files
    '''    
    bd_logger("Starting export_data...")    
    
    head_file = open(in_file_path, 'rb')
    
    data_file_path = in_file_path[0:-3] + "WAD"
    data_file = open(data_file_path, 'rb')
    
    
    if not os.path.exists(out_folder_path):
        os.makedirs(out_folder_path)      
        
        
    for i in range(999999):
        try:
            file_offset = struct.unpack("<L", head_file.read(4))[0]
            file_size = struct.unpack("<L", head_file.read(4))[0]
        except:
            bd_logger("End of file...")
            return
        
        file_path = ""
        path_len = 0
        str_start_offset = head_file.tell()
        while 1:
            back_offset = head_file.tell()
            ch = struct.unpack("c", head_file.read(1))[0].decode("utf8")
            if ch != "\x00":
                path_len += 1
                file_path += ch 
            else:
                head_file.seek(back_offset)
                break
        
        if path_len % 4 == 0:
            add_bytes = path_len + 4
        else:
            add_bytes = get_bytes(path_len, 4)
            
        head_file.seek(str_start_offset + add_bytes)
        
        out_file_path = out_folder_path + file_path
        out_file_folder_path = out_file_path.split("\\")[0:-1]
        out_file_folder_path = "\\".join(out_file_folder_path)
        bd_logger(str(i+1) + ") " + out_file_path)
        
        
        if not os.path.exists(out_file_folder_path):
            os.makedirs(out_file_folder_path)         
        
        data_file.seek(file_offset)
        data = data_file.read(file_size)
        out_file = open(out_file_path, "wb+")
        out_file.write(data)
        out_file.close()
   
    
    data_file.close()
    head_file.close()
    bd_logger("Ending export_data...")    
    
    
    
    
def main():
    
    main_switch = 1

    if main_switch == 1:
        #p_in_file_path = "C:\\Users\\Arek\\Desktop\\aaaTONY\\SKATE5.HED"
        #p_out_folder_path = "C:\\Users\\Arek\\Desktop\\aaaTONY\\SKATE5.WAD_OUT"
        
        p_in_file_path = "C:\\Users\\Arek\\Desktop\\aaaTONY\\MUSIC\\MUSIC.HED"
        p_out_folder_path = "C:\\Users\\Arek\\Desktop\\aaaTONY\\MUSIC\\MUSIC.WAD_OUT"        
        export_data(p_in_file_path, p_out_folder_path)
  
    else:
        print("Wrong option selected!")
        
        
    
    bd_logger("End of main...")    
    
    
    
main()




