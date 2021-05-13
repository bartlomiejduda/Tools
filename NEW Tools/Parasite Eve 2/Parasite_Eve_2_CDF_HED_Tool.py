# -*- coding: utf-8 -*-

'''
Copyright © 2021  Bartłomiej Duda
License: GPL-3.0 License 
'''


# Program tested on Python 3.7.0
# It should be used with Parasite Eve 2 (PS1)

# Ver    Date        Author               Comment
# v0.1   07.05.2021  Bartlomiej Duda      -
# v0.2   08.05.2021  Bartlomiej Duda      Export function for STAGE0 completed
# v0.3   13.05.2021  Bartlomiej Duda      Added initial STAGE1-STAGE3 logic

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


def read_toc(in_file):
    count = 0
    r_offset_list = []
    while 1:
        count += 1
        f_id = struct.unpack("<L", in_file.read(4))[0]
        f_offset_or_size = struct.unpack("<L", in_file.read(4))[0]
        f_real_offset_or_size = f_offset_or_size * 2048
        
        if (f_id == 0 and count != 1) or f_id == 4294967295:
            break    
        
        r_offset_list.append(f_real_offset_or_size)
        
        #print(str(count) + ") " + 
              #"ID: " + str(f_id).ljust(10) + "\t" +
              #" offset: " + str(f_offset_or_size).ljust(10) + "\t" +
              #" real_offset: " + str(f_real_offset_or_size).ljust(10) + "\t"
              #)   
        
    return r_offset_list
        

block_names_mapping = { 
                         0: "Room package block",
                         1: "Image", 
                         2: "CLUT", 
                         4: "CAP2 Text", 
                         5: "Room backgrounds",  
                         6: "SPK/MPK music program",  
                         7: "ASCII text", 
                         #96: "Sounds", 
                      }

file_ext_mapping = {
                      0: ".pe2pkg",
                      1: ".pe2img",
                      2: ".pe2clut",
                      4: ".pe2cap2",
                      5: ".bs",
                      6: ".spk",
                      7: ".txt",
                      #96: ".pe2snd"
                   }


def get_block_name(in_block_type):
    return block_names_mapping.get(in_block_type, "Unknown_Block_Name")

def get_file_ext(in_block_type):
    return file_ext_mapping.get(in_block_type, ".BIN")


def export_data(in_hed_file_path, in_cdf_file_path, out_folder_path):
    '''
    Function for exporting data from CDF files
    '''    
    bd_logger("Starting export_data...")  
    
    if not os.path.exists(os.path.dirname(out_folder_path)):  
        os.makedirs(os.path.dirname(out_folder_path))     
    
    cdf_file = open(in_cdf_file_path, 'rb')
    cdf_size = os.path.getsize(in_cdf_file_path)
    
    hed_flag = 0
    if in_hed_file_path != "" and in_hed_file_path is not None:
        hed_file = open(in_hed_file_path, 'rb')
        hed_file.read(120) # skip header 
        hed_global_toc = read_toc(hed_file) # read TOC from HED file
        hed_flag = 1
        
    # get data using TOC from HED file (STAGE0 logic)
    if hed_flag == 1:
        
        hed_global_toc.append(cdf_size)
        f_size_list = []
        
        for i in range(len(hed_global_toc) - 1):
            f_size = hed_global_toc[i+1] - hed_global_toc[i]
            f_size_list.append(f_size)
            f_r_offset = hed_global_toc[i]
            
            if f_size != 0:
                #print("f_r_offset: " + str(f_r_offset).ljust(10) + 
                      #" f_size: " + str(f_size).ljust(10)
                      #)
    
                # check file type
                f_ext = ""
                back_offset = cdf_file.tell()
                comp_flag = -1
                try:
                    b_type = struct.unpack("<B", cdf_file.read(1))[0] 
                    comp_flag = struct.unpack("<B", cdf_file.read(1))[0] 
                    block_name = get_block_name(b_type)
                    f_ext = get_file_ext(b_type)
                    print(comp_flag)
                except:
                    print("Couldn't read signature!")
                finally:
                    cdf_file.seek(back_offset)
                    
                if "Unknown" in block_name: 
                    try: # try to detect file type by signature
                        sign = cdf_file.read(4).decode("utf8")
                        if sign == "hMPK":
                            f_ext = ".hmpk"
                    except:
                        pass
                    finally:
                        cdf_file.seek(back_offset)
                        
                if f_ext == "":
                    f_ext = ".bin"
        
                # read data 
                cdf_file.seek(f_r_offset)
                cdf_file.read(16) # skip data block header
                f_size -= 16
                f_data = cdf_file.read(f_size)
                
                f_name = "file" + str(i+1) + f_ext
                f_path = out_folder_path + f_name 
                print(f_path)
                
                out_file = open(f_path, "wb+")
                out_file.write(f_data)
                out_file.close()
    
    
    
    # get data using TOC from CDF file  (STAGE1-STAGE3 logic)
    else:
        global_toc = read_toc(cdf_file)
        num_of_glob_toc_entries = len(global_toc)
        glob_offset_list = []
        
        glob_offset = 2048
        cdf_file.seek(glob_offset) # go to first local TOC

        glob_offset_list.append(glob_offset)
        for glob_i in range(num_of_glob_toc_entries-1): # loop for calculating global offsets
            glob_offset += global_toc[glob_i]
            glob_offset_list.append(glob_offset)
            
        for glob_j in range(num_of_glob_toc_entries): # FOLDER LOOP
            fold_offset = glob_offset_list[glob_j]
            fold_size = global_toc[glob_j]
            fold_end_offset = fold_offset + fold_size
            print("FOLDER " + str(glob_j+1) + ", off: " + str(fold_offset) + " size: " + str(fold_size) )
        
            
            cdf_file.seek(fold_offset) # go to first local TOC in folder
            
            local_toc = read_toc(cdf_file)
            num_of_loc_toc_entries = len(local_toc)
            
            
            loc_offset_list = []
            for loc_i in range(num_of_loc_toc_entries): # loop for calculating local offsets
                file_offset = fold_offset + local_toc[loc_i]
                loc_offset_list.append(file_offset)

            loc_offset_list.append(fold_end_offset)
            
            loc_size_list =[]
            for loc_j in range(num_of_loc_toc_entries): # loop for calculating local sizes
                loc_size = loc_offset_list[loc_j+1] - loc_offset_list[loc_j] 
                loc_size_list.append(loc_size)
              
                
            for loc_k in range(num_of_loc_toc_entries):
                subfold_start = loc_offset_list[loc_k]
                subfold_size = loc_size_list[loc_k]
                subfold_end = subfold_start + subfold_size
                print("\t SUB_FOLD " + str(loc_k+1) + ", off: " + str(subfold_start) + " size: " + str(subfold_size) )
                
                
                cdf_file.seek(subfold_start) # go to first file in subfolder
                
                f_count = 0
                f_sum = 0
                while 1:
                    f_count += 1
                    back_offset = cdf_file.tell()
                    file_type = struct.unpack("B", cdf_file.read(1))[0]
                    comp_flag = struct.unpack("B", cdf_file.read(1))[0]
                    cdf_file.read(2) # unknown 
                    file_ext = get_file_ext(file_type)
                    file_desc = get_block_name(file_type)
                    file_name = "fold" + str(glob_j) + "_sub" + str(loc_k+1) + "_file" + str(f_count) + file_ext
                    file_path = out_folder_path + file_name
                    if file_type < 10:
                        file_size = struct.unpack("<L", cdf_file.read(4))[0] * 2048
                    else:
                        file_size = subfold_end - back_offset
                        
                    print("\t\t FILE " + str(f_count) + ", f_type: " + str(file_type) + " f_size: " + str(file_size) + " f_name: " + str(file_name) )
                    
                    #if file_type >= 10:
                        #print ("\t\t !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
                    f_sum += file_size
                    
                    if file_type < 10:
                        cdf_file.seek(back_offset + 16)
                        file_data = cdf_file.read(file_size - 16)
                    else:
                        cdf_file.seek(back_offset)
                        file_data = cdf_file.read(file_size)                        
                    #print("\t\t" + file_path)
                    
                    out_file = open(file_path, "wb+")
                    out_file.write(file_data)
                    out_file.close()
                    
                    
                    
                    
                    
                    cdf_file.seek(back_offset + file_size) # go to the next file in subfolder
                    
                    if cdf_file.tell() >= subfold_end:
                        break
                    
                #print("\t\ttotal_f_sizes_in_subfolder: " + str(f_sum))



   
    if hed_flag == 1:
        hed_file.close()
    cdf_file.close()
    bd_logger("Ending export_data...")    
    
    
    
    
def main():
    '''
    Main function of this program. If you are planning to use it,
    you should adjust paths first.
    '''   
    main_switch = 1
    # 1 - data export 
    

    if main_switch == 1:
        #p_in_hed_file_path = "C:\\Users\\Arek\\Desktop\\Parasite Eve 2 [SLUS 010-42]\out\\STAGE0.HED"
        #p_in_cdf_file_path = "C:\\Users\\Arek\\Desktop\\Parasite Eve 2 [SLUS 010-42]\out\\STAGE0.CDF"
        #p_out_folder_path = "C:\\Users\\Arek\\Desktop\\Parasite Eve 2 [SLUS 010-42]\out\\STAGE0.CDF_OUT\\"
        
        p_in_hed_file_path = ""
        p_in_cdf_file_path = "C:\\Users\\Arek\\Desktop\\Parasite Eve 2 [SLUS 010-42]\out\\STAGE2.CDF"
        p_out_folder_path = "C:\\Users\\Arek\\Desktop\\Parasite Eve 2 [SLUS 010-42]\out\\STAGE2.CDF_OUT\\"        
        
        
        export_data(p_in_hed_file_path, p_in_cdf_file_path, p_out_folder_path)
        
    else:
        bd_logger("Wrong option selected!")
        
        
    
    bd_logger("End of main...")    
    
    
    
main()