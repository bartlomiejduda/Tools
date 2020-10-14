# -*- coding: utf-8 -*-

# Tested on Python 3.8.0
# This tool should be used with Asobo Studio DPC, DXB and DPS archives

# Ver    Date        Author
# v0.1   13.10.2020  Bartlomiej Duda
# v0.2   13.10.2020  Bartlomiej Duda
# v0.3   14.10.2020  Bartlomiej Duda


import os
import sys
import struct
import math



def bd_logger(in_str):
    import datetime
    now = datetime.datetime.now()
    print(now.strftime("%d-%m-%Y %H:%M:%S") + " " + in_str)    
    

def export_data_type1(in_file_path, out_folder_path):
    '''
    Function for exporting data from DPS files
    '''    
    bd_logger("Starting export_data_type1...")    
    
    dps_file = open(in_file_path, 'rb')
    dps_file.seek(2048) #skip header 
    
    for j in range(100): #for each folder 
        out_fold_name = "fold" + str(j+1)
        
        curr_offset = dps_file.tell()
        print("curr_offset: " + str(curr_offset))
        
        if j > 0:
            while 1:
                back_offset = dps_file.tell()
                try:
                    check_byte = struct.unpack("<B", dps_file.read(1))[0]
                    if check_byte != 205:
                        dps_file.seek(back_offset)
                        break
                except:
                    bd_logger("End of file...")
                    return
                
        num_of_files = struct.unpack("<L", dps_file.read(4))[0]
        print("num_of_files: " + str(num_of_files))        
    
        for i in range(num_of_files): #for each file
            file_size = struct.unpack("<L", dps_file.read(4))[0] - 4
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


def export_data_type3(in_file_path, out_folder_path):
    '''
    Function for exporting data from DPC files
    '''    
    bd_logger("Starting export_data_type3...")    
    
    dpc_file = open(in_file_path, 'rb')
    dpc_file.seek(256)
    num_of_files = struct.unpack("<L", dpc_file.read(4))[0]
    dpc_file.seek(284)
    
    comp_size_arr = []
    for i in range(num_of_files):
        dpc_file.read(4)
        uncomp_size = struct.unpack("<L", dpc_file.read(4))[0]
        comp_size = struct.unpack("<L", dpc_file.read(4))[0]
        comp_size_arr.append(comp_size)
        dpc_file.read(12)
        
    dpc_file.seek(2048)
    
    if not os.path.exists(out_folder_path):
        os.makedirs(out_folder_path)      
    
    for i in range(num_of_files):
        file_data = dpc_file.read(comp_size_arr[i])
        out_file_path = out_folder_path + "file" + str(i+1) + ".bin"
        print(out_file_path)
        
        out_file = open(out_file_path, "wb+")
        out_file.write(file_data)
        out_file.close()
    
    
    dpc_file.close()
    bd_logger("Ending export_data_type3...")       



def export_data_type4(in_file_path, out_folder_path):
    '''
    Function for exporting data from DPS files
    '''    
    bd_logger("Starting export_data_type4...")    
    
    dpc_file = open(in_file_path, 'rb')
    dpc_file.seek(260)
    num_of_files = struct.unpack("<L", dpc_file.read(4))[0]
    dpc_file.seek(284)
    
    comp_size_arr = []
    for i in range(num_of_files):
        dpc_file.read(4)
        uncomp_size = struct.unpack("<L", dpc_file.read(4))[0]
        comp_size = struct.unpack("<L", dpc_file.read(4))[0]
        comp_size_arr.append(comp_size)
        dpc_file.read(12)
        
    dpc_file.seek(2048)
    
    if not os.path.exists(out_folder_path):
        os.makedirs(out_folder_path)      
    
    for i in range(num_of_files):
        file_data = dpc_file.read(comp_size_arr[i])
        out_file_path = out_folder_path + "file" + str(i+1) + ".bin"
        print(out_file_path)
        
        out_file = open(out_file_path, "wb+")
        out_file.write(file_data)
        out_file.close()
    
    
    dpc_file.close()
    bd_logger("Ending export_data_type4...")       

    
    
def main():
    
    main_switch = 4
    # Select main_switch value for your game:
    #
    # 1 - export data from those games:
    #       * Sitting Ducks PS2 DPS files (v1.19)
    #       * The Mummy: The Animated Series PS2 DPS files (v1.51)
    # 2 - export data from those games:
    #       * Garfield 2 PC DPC files (v1.08.40.02)
    # 3 - export data from those games:
    #       * CT Special Forces: Fire for Effect (Nemesis Strike) PC (v1.81)
    #       * CT Special Forces: Fire for Effect (Nemesis Strike) XBOX (v1.81)
    # 4 - export data from those games:
    #       *  	Ratatouille PS2 (v1.06.63.06)    

    
    if main_switch == 1:
        p_in_file_path = "C:\\Users\\Arek\\Desktop\\DPC_RESEARCH\\Mummy PS2\\SHARED.DPS"
        p_out_folder_path = "C:\\Users\\Arek\\Desktop\\DPC_RESEARCH\\Mummy PS2\\SHARED.DPS_OUT\\"           
        export_data_type1(p_in_file_path, p_out_folder_path)
        
    elif main_switch == 2:
        p_in_file_path = "C:\\Users\\Arek\\Desktop\\DPC_RESEARCH\\Ratatuj PS2\\FONTES.DPS"
        p_out_folder_path = "C:\\Users\\Arek\\Desktop\\DPC_RESEARCH\\Ratatuj PS2\\FONTES.DPS_OUT\\"             
        export_data_type2(p_in_file_path, p_out_folder_path)  
        
    elif main_switch == 3:
        p_in_file_path = "C:\\Users\\Arek\\Desktop\\DPC_RESEARCH\\CT Special Forces XBOX\\FONTS.DXB"
        p_out_folder_path = "C:\\Users\\Arek\\Desktop\\DPC_RESEARCH\\CT Special Forces XBOX\\FONTS.DXB_OUT\\"             
        export_data_type3(p_in_file_path, p_out_folder_path)    
        
    elif main_switch == 4:
        #p_in_file_path = "C:\\Users\\Arek\\Desktop\\DPC_RESEARCH\\Ratatuj PS2\\CT.DPS"
        #p_out_folder_path = "C:\\Users\\Arek\\Desktop\\DPC_RESEARCH\\Ratatuj PS2\\CT.DPS_OUT\\"    
        
        p_in_file_path = "C:\\Users\\Arek\\Desktop\\DPC_RESEARCH\\WALL-E PS2\\MENU.DPS"
        p_out_folder_path = "C:\\Users\\Arek\\Desktop\\DPC_RESEARCH\\WALL-E PS2\\MENU.DPS_OUT\\"            
        export_data_type4(p_in_file_path, p_out_folder_path)           
        
            
    else:
        print("Wrong option selected!")
        
        
    
    bd_logger("End of main...")    
    
    
    
main()