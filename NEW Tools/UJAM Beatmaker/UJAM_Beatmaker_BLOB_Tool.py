# -*- coding: utf-8 -*-

'''
Copyright © 2021  Bartłomiej Duda
License: GPL-3.0 License 
'''


# Program tested on Python 3.7.0
# It should be used with BLOB files from UJAM Beatmaker

# Ver    Date        Author               Comment
# v0.1   06.03.2021  Bartlomiej Duda      -

import os
import sys
import struct
import datetime
import json


def bd_logger(in_str):
    '''
    Function for logging debug messages
    '''   
    now = datetime.datetime.now()
    print(now.strftime("%d-%m-%Y %H:%M:%S") + " " + in_str)    
    

def export_data(in_file_path, out_folder_path):
    '''
    Function for exporting data from BLOB files
    '''    
    bd_logger("Starting export_data...")  
    
    if not os.path.exists(out_folder_path):
        os.makedirs(out_folder_path)      
    
    blob_file = open(in_file_path, 'rb')
    magic = blob_file.read(4)
    size_of_info_json = struct.unpack("<L", blob_file.read(4))[0]
    info_json = blob_file.read(size_of_info_json).decode("utf8")
    parsed_info_json = json.loads(info_json)
    info_json_instr_dict = parsed_info_json["instruments"][0]
    offset_of_instruments_json = blob_file.tell() + info_json_instr_dict["at_byte"]
    size_of_instruments_json = info_json_instr_dict["size_bytes"]
    num_of_wav_entries = int((offset_of_instruments_json - blob_file.tell() ) / 304)
    
    print("num_of_wav_entries: " + str(num_of_wav_entries))
    
    
    for i in range (num_of_wav_entries):
        unknown = blob_file.read(54)
        wav_path = blob_file.read(250).decode("utf8").rstrip("\x00")
    
    
    instrument_json = blob_file.read(size_of_instruments_json)
    
    
    num_of_arrays = 156    # hardcoded 
    
    arr_of_sizes = []
    arr_of_arrays = []
    
    for curr_array in range(num_of_arrays):
        
        num_of_offsets = struct.unpack("<L", blob_file.read(4))[0]
        
        arr_offsets = []
        for curr_offset in range(num_of_offsets+1):
            pos = blob_file.tell()
            offset = struct.unpack("<L", blob_file.read(4))[0]
            arr_offsets.append(offset)
            
            
        arr_of_sizes.append(num_of_offsets)
        arr_of_arrays.append(arr_offsets)
            
            
            
    uuid = blob_file.read(36)
    
    data_start_offset = blob_file.tell()
    print("data_start_offset: " + str(data_start_offset))
    
    for i in range(num_of_arrays):
        
        arr_size = arr_of_sizes[i]
        
        file_size = 0
        for j in range(arr_size-1):
            
            arr_offset = arr_of_arrays[i][j]
            arr_offset_end = arr_of_arrays[i][j+1]
            
            file_size += (arr_offset_end - arr_offset)

            
        file_name = "file" + str(i+1) + ".vgmstream"
        
        file_path = out_folder_path + file_name
        print(file_path)
        file_data = blob_file.read(file_size)
        
        out_file = open(file_path, "wb+")
        out_file.write(file_data)
        out_file.close()
    


    
    blob_file.close()
    bd_logger("Ending export_data...")    
    
    
    
    
def main():
    '''
    Main function of this program. If you are planning to use it,
    you should adjust paths first.
    '''   
    main_switch = 1
    # 1 - data export 
    

    if main_switch == 1:
        p_in_file_path = "C:\\Users\\Arek\\Desktop\\BM-EDEN.blob"
        p_out_folder_path = "C:\\Users\\Arek\\Desktop\\BM-EDEN.blob_OUT\\"
        export_data(p_in_file_path, p_out_folder_path)
        
    else:
        bd_logger("Wrong option selected!")
        
        
    
    bd_logger("End of main...")    
    
    
    
main()