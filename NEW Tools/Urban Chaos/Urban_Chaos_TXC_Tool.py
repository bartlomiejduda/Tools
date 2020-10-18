# -*- coding: utf-8 -*-

# Tested on Python 3.8.0
# This tool should be used with Urban Chaos PC

# Ver    Date        Author
# v0.1   18.10.2020  Bartlomiej Duda

import os
import sys
import struct



def bd_logger(in_str):
    import datetime
    now = datetime.datetime.now()
    print(now.strftime("%d-%m-%Y %H:%M:%S") + " " + in_str)    
    


def export_txc(in_file_path, out_folder_path):
    '''
    Function for exporting data from TXC files
    '''    
    bd_logger("Starting export_txc...")    
    
    txc_file = open(in_file_path, 'rb')
    
    num_of_files = struct.unpack("<L", txc_file.read(4))[0]
    #print("num_of_files: " + str(num_of_files))
    
    offset_arr = []
    for i in range(num_of_files):
        file_offset = struct.unpack("<L", txc_file.read(4))[0]
        offset_arr.append(file_offset)
        
    size_arr = []
    for i in range(num_of_files):
        file_size = struct.unpack("<L", txc_file.read(4))[0]
        size_arr.append(file_size)    
    
    if not os.path.exists(out_folder_path):
        os.makedirs(out_folder_path)      
    
    file_count = 0    
    for i in range(num_of_files):
        if offset_arr[i] != 0 and size_arr[i] != 0:
            file_count += 1
            #print("File " + str(file_count) + ": " + "file_off=" + str(offset_arr[i]) + " file_size=" + str(size_arr[i]))
            txc_file.seek(offset_arr[i])
            file_data = txc_file.read(size_arr[i])
            out_path = out_folder_path + "file" + str(file_count) + ".txc"
            print(out_path)
            
            out_file = open(out_path, "wb+")
            out_file.write(file_data)
            out_file.close()
   
    
    txc_file.close()
    bd_logger("Ending export_txc...")    
    
    
    
    
def main():
    
    main_switch = 1
    # 1 - txc export 
    
    
    if main_switch == 1:
        p_in_file_path = "E:\\STEAM_GRY_IDE_1\\steamapps\\common\\Urban Chaos\\clumps\\mib.txc"
        p_out_folder_path = "E:\\STEAM_GRY_IDE_1\\steamapps\\common\\Urban Chaos\\clumps\\mib.txc_OUT\\"
        export_txc(p_in_file_path, p_out_folder_path)
    
    else:
        print("Wrong option selected!")
        
        
    
    bd_logger("End of main...")    
    
    
    
main()