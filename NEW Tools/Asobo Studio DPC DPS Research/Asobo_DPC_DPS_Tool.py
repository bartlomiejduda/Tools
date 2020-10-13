# -*- coding: utf-8 -*-

# Tested on Python 3.8.0
# This tool should be used with Asobo Studio DPC and DPS archives

# Ver    Date        Author
# v0.1   13.10.2020  Bartlomiej Duda
# v0.2   13.10.2020  Bartlomiej Duda


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



def export_data_type1(in_file_path, out_folder_path):
    '''
    Function for exporting data from DPS files
    '''    
    bd_logger("Starting export_data_type1...")    
    
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
    bd_logger("Ending export_data_type1...")    
    


def export_data_type2(in_file_path, out_folder_path):
    '''
    Function for exporting data from DPC files
    '''    
    bd_logger("Starting export_data_type2...")    
    
    dpc_file = open(in_file_path, 'rb')
    
    dpc_file.seek(256)
    num_of_entries = struct.unpack("<L", dpc_file.read(4))[0]
    print("num_of_entries: " + str(num_of_entries))
    
    data_block_size_arr = []
    dpc_file.seek(288)
    for i in range(num_of_entries):
        data_block_size = struct.unpack("<L", dpc_file.read(4))[0]
        data_size = struct.unpack("<L", dpc_file.read(4))[0]
        x3 = struct.unpack("<L", dpc_file.read(4))[0]
        x4 = struct.unpack("<L", dpc_file.read(4))[0]
        x5 = struct.unpack("<L", dpc_file.read(4))[0]
        x6 = struct.unpack("<L", dpc_file.read(4))[0]
        data_block_size_arr.append(data_block_size)
        #print("data_block_size: " + str(data_block_size) + " data_size: " + str(data_size) + " x3: " + str(x3) + " x4: " + str(x4) + " x5: " + str(x5) + " x6: " + str(x6) )
    
        if not os.path.exists(out_folder_path):
            os.makedirs(out_folder_path)      
    
    
    dpc_file.seek(2048)    
    for i in range(num_of_entries):
        size = data_block_size_arr[i]
        block_data = dpc_file.read(size)
        out_file_path = out_folder_path + "data_block_file" + str(i+1) + ".bin"
        print(out_file_path)
        
        out_file = open(out_file_path, "wb+")
        out_file.write(block_data)
        out_file.close()
        

    
    
    dpc_file.close()
    bd_logger("Ending export_data_type2...")      
    
    
def main():
    
    main_switch = 2
    # 1 - export data from those games:
    #       * Sitting Ducks PS2 DPS files (v1.19)
    #       * The Mummy: The Animated Series PS2 DPS files (v1.51)
    # 2 - export data from those games:
    #       * Garfield 2 PC DPC files (v1.08.40.02)
    

    
    if main_switch == 1:
        p_in_file_path = "C:\\Users\\Arek\\Desktop\\DPC_RESEARCH\\Mummy PS2\\SHARED.DPS"
        p_out_folder_path = "C:\\Users\\Arek\\Desktop\\DPC_RESEARCH\\Mummy PS2\\SHARED.DPS_OUT\\"           
        export_data_type1(p_in_file_path, p_out_folder_path)
        
    elif main_switch == 2:
        #p_in_file_path = "C:\\Users\\Arek\\Desktop\\DPC_RESEARCH\\Garfield PC\\P_GARFLD.DPC"
        #p_out_folder_path = "C:\\Users\\Arek\\Desktop\\DPC_RESEARCH\\Garfield PC\\P_GARFLD.DPC_OUT\\"    
        
        p_in_file_path = "C:\\Users\\Arek\\Desktop\\DPC_RESEARCH\\Garfield PC\\FONTES.DPC"
        p_out_folder_path = "C:\\Users\\Arek\\Desktop\\DPC_RESEARCH\\Garfield PC\\FONTES.DPC_OUT\\"           
        export_data_type2(p_in_file_path, p_out_folder_path)        
        
            
    else:
        print("Wrong option selected!")
        
        
    
    bd_logger("End of main...")    
    
    
    
main()