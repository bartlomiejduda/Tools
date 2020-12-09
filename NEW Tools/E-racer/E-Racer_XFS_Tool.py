# -*- coding: utf-8 -*-

'''
Copyright © 2020  Bartłomiej Duda
License: GPL-3.0 License 
'''


# Program tested on Python 3.7.0
# It should be used with E-racer (PC)

# Ver    Date        Author               Comment
# v0.1   02.12.2020  Bartlomiej Duda      -
# v0.2   08.12.2020  Bartlomiej Duda      Fixed data extraction

import os
import sys
import struct
import datetime
from operator import itemgetter


def bd_logger(in_str):
    '''
    Function for logging debug messages
    '''   
    now = datetime.datetime.now()
    print(now.strftime("%d-%m-%Y %H:%M:%S") + " " + in_str)    
    

def export_data(in_file_path, out_folder_path, hash_dump_path):
    '''
    Function for exporting data from XFS files
    '''    
    bd_logger("Starting export_data...")  
    
    if not os.path.exists(out_folder_path):
        os.makedirs(out_folder_path)      
    
    xfs_file = open(in_file_path, 'rb')
    xfs_size = os.path.getsize(in_file_path)
    
    
    magic = struct.unpack("<8s", xfs_file.read(8))[0].decode("utf8")
    
    if magic != "DID DAT" + '\x1a':
        bd_logger("It is not XFS archive! Ending...")
        return
    
    xfs_file.seek(20)
    data_start_offset = struct.unpack("<L", xfs_file.read(4))[0]
    
    xfs_file.seek(28)
    DAT_info_offset = struct.unpack("<L", xfs_file.read(4))[0]
    
    xfs_file.seek(44)
    hash_index_offset = struct.unpack("<L", xfs_file.read(4))[0]
    
    num_of_hashes = int((xfs_size - hash_index_offset) / 8)
    
    
    
    hash_arr = []
    if len(hash_dump_path) > 1: # load hashes and fienames from hash dump if path is defined
        hash_dump_file = open(hash_dump_path, "rt")
        hash_count = 0
        for line in hash_dump_file:
            hash_count += 1
            hash_entry = hex(int(line.split("=")[0], 16))
            name_entry = line.split("=")[1].rstrip("\n")
            
            hash_entry_arr = []
            hash_entry_arr.append(hash_entry)
            hash_entry_arr.append(name_entry)
            
            hash_arr.append(hash_entry_arr)
    
    
    
    
    xfs_file.seek(hash_index_offset)
    index = 0
    hash_b_arr = []
    for i in range(num_of_hashes): # read hashes and offsets from hash index in XFS file
        index += 1
        hash_b_entry = hex(struct.unpack("<L", xfs_file.read(4))[0])
        offset_b_entry = struct.unpack("<L", xfs_file.read(4))[0]
        
        hash_b_entry_arr = []
        hash_b_entry_arr.append(index)
        hash_b_entry_arr.append(hash_b_entry)
        hash_b_entry_arr.append(offset_b_entry)
    
        hash_b_arr.append(hash_b_entry_arr)
        
    hash_b_arr_sorted = sorted(hash_b_arr, key=itemgetter(2)) # sort list
    
    temp_entry = ['temp1', 'temp2', DAT_info_offset]  # DAT_info_offset is also data end offset, it is needed for calculations
    hash_b_arr_sorted.append(temp_entry)
    
    for i in range(num_of_hashes): #calculate size
        file_size = hash_b_arr_sorted[i+1][2] - hash_b_arr_sorted[i][2]
        hash_b_arr_sorted[i].append(file_size)
        
    hash_b_arr_sorted.pop() # remove temp entry
    
    f_count = 0
    match_flag = 0
    for hash_c_entry in hash_b_arr_sorted:  # try to get filenames from hash dump
        f_count += 1
        hash_c = hash_c_entry[1]
        
        match_flag = 0
        for hash_d_entry in hash_arr:
            hash_d = hash_d_entry[0]
            
            if hash_c == hash_d:
                match_flag = 1
                filename = hash_d_entry[1]
                hash_c_entry.append(filename)
                break
            
        if match_flag != 1:
            filename = "file" + str(f_count+1) + ".bin"
            hash_c_entry.append(filename)
        
      
    for hash_e_entry in hash_b_arr_sorted: # start data extraction process 
        file_e_offset = hash_e_entry[2]
        file_e_comp_size = hash_e_entry[3] - 8
        file_e_name = hash_e_entry[4]
        
        xfs_file.seek(file_e_offset)
        file_e_uncomp_size = xfs_file.read(4)
        file_e_comp_flag = struct.unpack("<L", xfs_file.read(4))[0]
        
        file_e_ext = ""
        if file_e_comp_flag == 1:
            file_e_ext = ".ra"
            
        file_e_data = xfs_file.read(file_e_comp_size)
        file_e_path = out_folder_path + file_e_name + file_e_ext
        print(file_e_path)
        
        file_e_fold_path = file_e_path.split("\\")[:-1]
        file_e_fold_path = "\\".join(file_e_fold_path)
        
        if not os.path.exists(file_e_fold_path):
            os.makedirs(file_e_fold_path)        
        
        out_file = open(file_e_path, "wb+")
        out_file.write(file_e_data)
        out_file.close()
    
    
    xfs_file.close()
    bd_logger("Ending export_data...")    
    
    
    
    
def main():
    '''
    Main function of this program. If you are planning to use it,
    you should adjust paths first.
    '''   
    main_switch = 1
    # 1 - data export 
    

    if main_switch == 1:
        p_in_file_path = "D:\\INNE_GRY\\eRacer DEMO\\eRacer.xfs"
        p_out_folder_path = "D:\\INNE_GRY\\eRacer DEMO\\eRacer.xfs_OUT\\"
        p_hash_dump_path = "eracer_hash_dump.txt" # Leave this empty if you don't have any hash dump
        export_data(p_in_file_path, p_out_folder_path, p_hash_dump_path)
        
    else:
        print("Wrong option selected!")
        
        
    
    bd_logger("End of main...")    
    
    
    
main()