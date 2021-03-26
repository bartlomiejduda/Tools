# -*- coding: utf-8 -*-

'''
Copyright © 2021  Bartłomiej Duda
License: GPL-3.0 License 
'''


# Program tested on Python 3.7.0
# It should be used with Kill Switch

# Ver    Date        Author               Comment
# v0.1   26.03.2021  Bartlomiej Duda      -

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
    Function for exporting data from DAT files
    '''    
    bd_logger("Starting export_data...")  
    
    if not os.path.exists(out_folder_path):
        os.makedirs(out_folder_path)      
    
    dat_file = open(in_file_path, 'rb')
    
    #header chunk
    chunk_type = struct.unpack("<L", dat_file.read(4))[0]
    if chunk_type != 1817:
        log_msg = "This is not valid DAT file from Kill Switch!"
        bd_logger(log_msg)
        raise Exception(log_msg)
    chunk_size = struct.unpack("<L", dat_file.read(4))[0]
    RW_ID = dat_file.read(4)
    chunk_data = dat_file.read(chunk_size)
    
    #data start chunk 
    chunk_type = struct.unpack("<L", dat_file.read(4))[0]
    if chunk_type != 1798:
        log_msg = "This is not valid data start chunk!"
        bd_logger(log_msg)
        raise Exception(log_msg)
    chunk_size = struct.unpack("<L", dat_file.read(4))[0]
    RW_ID = dat_file.read(4)
    chunk_data = dat_file.read(chunk_size)
    
    # data chunks
    chunk_num = 0
    while 1:
        chunk_num += 1
        chunk_type = struct.unpack("<L", dat_file.read(4))[0]
        chunk_type_s = ""
        if (chunk_type == 1814):
            chunk_type_s = str(chunk_type) + " - container"
        elif (chunk_type == 1798):
            curr_offset = dat_file.tell() - 4
            log_msg = "Encountered data end chunk at offset " + str(curr_offset) + ". Exiting..."
            bd_logger(log_msg)
            break
        else:
            chunk_type_s = str(chunk_type) + " - unknown chunk type"
        
        print("CHUNK_NUM: " + str(chunk_num) )
        print("CHUNK_TYPE: " + chunk_type_s)
        chunk_size = struct.unpack("<L", dat_file.read(4))[0]
        RW_ID = dat_file.read(4)
        chunk_data_offset = dat_file.tell()
        GUID_path_len = struct.unpack("<L", dat_file.read(4))[0]
        GUID_path_string = dat_file.read(GUID_path_len).decode("utf8").replace("\x00", "").replace("M:", "\nM:") + "\n"
        offset_diff = dat_file.tell() - chunk_data_offset
        dat_file.read(4) # some size?
        chunk_data = dat_file.read(chunk_size - offset_diff - 4)
        
        subchunk_type = GUID_path_string.split("\n")[0].split("}")[1]
        print("SUBCHUNK_TYPE: " + subchunk_type)
        
        file_path = GUID_path_string.split("\n")[1].lstrip("M:\\")
        
        f_out_path = out_folder_path + file_path
        f_out_folder =  "\\".join( f_out_path.split("\\")[0:-1] )
        print(f_out_path + "\n\n")
        

        if not os.path.exists(f_out_folder):
            os.makedirs(f_out_folder)   
            
        out_file = open(f_out_path, "wb+")
        out_file.write(chunk_data)
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
        p_in_file_path = "C:\\Users\\Arek\\Desktop\\DESERT3.dat"
        p_out_folder_path = "C:\\Users\\Arek\\Desktop\\DESERT3.dat_OUT\\"
        export_data(p_in_file_path, p_out_folder_path)
        
    else:
        bd_logger("Wrong option selected!")
        
        
    
    bd_logger("End of main...")    
    
    
    
main()