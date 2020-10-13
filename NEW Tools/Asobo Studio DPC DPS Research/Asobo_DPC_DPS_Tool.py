# -*- coding: utf-8 -*-

# Tested on Python 3.8.0
# This tool should be used with Asobo Studio DPC and DPS archives

# Ver    Date        Author
# v0.1   13.10.2020  Bartlomiej Duda


import os
import sys
import struct
import math



def bd_logger(in_str):
    import datetime
    now = datetime.datetime.now()
    print(now.strftime("%d-%m-%Y %H:%M:%S") + " " + in_str)    
    
def calculate_jump_offset(in_offset, in_value):
    check_val = in_offset / in_value
    
    if check_val == 1:
        return in_offset
    else:
        res_offset = math.ceil(check_val) * in_value
        return res_offset



def export_sitting_ducks_PS2(in_file_path, out_folder_path):
    '''
    Function for exporting data from DPS files
    '''    
    bd_logger("Starting export_sitting_ducks_PS2...")    
    
    dps_file = open(in_file_path, 'rb')
    
    
    dps_file.seek(2048) #skip header 
    

    
    
    for j in range(10): #for each folder 
        out_fold_name = "fold" + str(j+1)
        
        curr_offset = dps_file.tell()
        print("curr_offset: " + str(curr_offset))
        
        #jump_offset = calculate_jump_offset(curr_offset, 2048)
        #print("jump_offset: " + str(jump_offset))
        #dps_file.seek(jump_offset)
        
        if j > 0:
            while 1:
                back_offset = dps_file.tell()
                try:
                    check_byte = struct.unpack("<B", dps_file.read(1))[0]
                    #print("ch_byte: " + str(check_byte))
                    if check_byte != 205:
                        dps_file.seek(back_offset)
                        break
                except:
                    bd_logger("End of file...")
                    return
                
        
        #temp = dps_file.tell() / 1024
        #print("DEBUG_OFF: " + str(temp))
        
        num_of_files = struct.unpack("<L", dps_file.read(4))[0]
        print("num_of_files: " + str(num_of_files))        
    
        for i in range(num_of_files): #for each file
            file_size = struct.unpack("<L", dps_file.read(4))[0] - 4
            #print("file_size: " + str(file_size))
            file_data = dps_file.read(file_size)
            out_subfolder_path = out_folder_path + out_fold_name
            out_file_path =  out_subfolder_path + "\\file" + str(i+1) + ".bin"
            print(out_file_path)
            
            if not os.path.exists(out_subfolder_path):
                os.makedirs(out_subfolder_path)    
                
            out_file = open(out_file_path, 'wb+')
            out_file.write(file_data)
            out_file.close()
  
    
    dps_file.close()
    bd_logger("Ending export_sitting_ducks_PS2...")    
    
    
    
    
def main():
    
    main_switch = 1
    # 1 - export data from Sitting Ducks PS2 DPS files (v1.19)

    
    if main_switch == 1:
        #p_in_file_path = "C:\\Users\\Arek\\Desktop\\DPC_RESEARCH\\Sitting Ducks PS2\\MENU.DPS"
        #p_out_folder_path = "C:\\Users\\Arek\\Desktop\\DPC_RESEARCH\\Sitting Ducks PS2\\MENU.DPS_OUT\\"
        
        p_in_file_path = "C:\\Users\\Arek\\Desktop\\DPC_RESEARCH\\Sitting Ducks PS2\\SHARED.DPS"
        p_out_folder_path = "C:\\Users\\Arek\\Desktop\\DPC_RESEARCH\\Sitting Ducks PS2\\SHARED.DPS_OUT\\"        
        export_sitting_ducks_PS2(p_in_file_path, p_out_folder_path)
        
            
    else:
        print("Wrong option selected!")
        
        
    
    bd_logger("End of main...")    
    
    
    
main()