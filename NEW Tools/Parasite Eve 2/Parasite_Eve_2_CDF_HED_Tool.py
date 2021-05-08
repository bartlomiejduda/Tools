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
                         96: "Sounds", 
                      }

file_ext_mapping = {
                      0: ".pe2pkg",
                      1: ".pe2img",
                      2: ".pe2clut",
                      4: ".pe2cap2",
                      5: ".bs",
                      6: ".spk",
                      7: ".txt",
                      96: ".pe2snd"
                   }


def get_block_name(in_block_type):
    return block_names_mapping.get(in_block_type, "Unknown_Block_Name")

def get_file_ext(in_block_type):
    return file_ext_mapping.get(in_block_type, "Unknown_File_Ext")


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
        f_size_list = []
        
        cdf_file.seek(2048) # go to first local TOC

        for i in range(num_of_glob_toc_entries):
            f_r_size = global_toc[i]   
            #print("GLOB f_r_size: " + str(f_r_size).ljust(10) )  
            
            f_data = cdf_file.read(f_r_size)
            f_name = "file" + str(i+1) + ".bin"
            f_path = out_folder_path + f_name
            print(f_path)
            
            out_file = open(f_path, "wb+")
            out_file.write(f_data)
            out_file.close()
        
        
        
        #loc_end_offset = 2048
        #for g_num in range(num_of_glob_toc_entries):
            #loc_start_offset = cdf_file.tell()
            
            #loc_end_offset += global_toc[g_num]

            #local_toc = read_toc(cdf_file)
            #num_of_loc_toc_entries = len(local_toc)
            #fold_name = "folder" + str(g_num + 1)

            #cdf_file.seek(loc_start_offset + 2048) # skip local TOC 
            
            #f_count = 0
            #while 1:
                #f_count += 1
                #back_offset = cdf_file.tell()
                #b_type = struct.unpack("<B", cdf_file.read(1))[0] 
                #comp_flag = struct.unpack("<B", cdf_file.read(1))[0] 
                #cdf_file.read(2)
                #if b_type == 96:
                    #f_size = 2048 
                    #cdf_file.seek(back_offset)
                #else:
                    #f_size = struct.unpack("<L", cdf_file.read(4))[0] * 2048 - 16
                    #cdf_file.read(8) # skip second part of the header
                #f_ext = get_file_ext(b_type)
                #f_name = "file" + str(f_count) + f_ext
                #f_path = out_folder_path + fold_name + "\\" + f_name
                ##print(f_path)
                
                
                #temp_off2 = cdf_file.tell()             
                #f_data = cdf_file.read(f_size)
                #curr_offset = cdf_file.tell()
                
                #print ( "f_name: " + str(f_name).ljust(15) +
                        #" data_start: " + str(temp_off2).ljust(10) +
                        #" data_end: " + str(curr_offset).ljust(10)
                        #)

                #if curr_offset >= loc_end_offset:
                    #print("loc_end_off: " + str(loc_end_offset) )
                    #print("BREAK!")
                    #break
            


   
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