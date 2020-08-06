# -*- coding: utf-8 -*-

# Tested on Python 3.8.0
# This tool should be used with Crash Mind Over Mutant PSP

# Ver    Date        Author
# v0.1   06.08.2020  Bartlomiej Duda




VERSION_NUM = "v0.1"

import os
import sys
import struct



def bd_logger(in_str):
    import datetime
    now = datetime.datetime.now()
    print(now.strftime("%d-%m-%Y %H:%M:%S") + " " + in_str)    
    


def export_RCF(in_file_path, out_folder_path):
    '''
    Function for exporting data from RCF files
    '''    
    bd_logger("Starting export_RCF...")    
    
    RCF_file = open(in_file_path, 'rb')
    
    #read header
    RCF_file.read(32) # ID string 
    RCF_file.read(4) # unknown 
    dir_offset = struct.unpack('<I', RCF_file.read(4))[0]
    dir_len = struct.unpack('<I', RCF_file.read(4))[0]
    filenames_arr_offset = struct.unpack('<I', RCF_file.read(4))[0]
    filenames_arr_size = struct.unpack('<I', RCF_file.read(4))[0]
    RCF_file.read(4) #dummy 
    num_of_files = struct.unpack('<I', RCF_file.read(4))[0]
    
    print("num_of_files: " + str(num_of_files) )
    
    #read directory
    for i in range(num_of_files):
        CRC = struct.unpack('<I', RCF_file.read(4))[0]
        file_offset = struct.unpack('<I', RCF_file.read(4))[0]
        file_size = struct.unpack('<I', RCF_file.read(4))[0]
        
        print( str(i+1) + ") " + "CRC=" + str(CRC) + " file_offset=" + str(file_offset) + " file_size=" + str(file_size) )
        
    
        
    #TODO
    
   
    
    RCF_file.close()
    bd_logger("Ending export_RCF...")    
    
    
    
    
def main():
    
    main_switch = 1
    # 1 - RCF export 

    if main_switch == 1:
        p_in_file_path = "C:\\Users\\Arek\\Desktop\\CRASH_MOM\\default.rcf"
        p_out_folder_path = "C:\\Users\\Arek\\Desktop\\CRASH_MOM\\DEFAULT_IKS"
        export_RCF(p_in_file_path, p_out_folder_path)

    else:
        print("Wrong option selected!")
        
        
    
    bd_logger("End of main...")    
    
    
    
main()