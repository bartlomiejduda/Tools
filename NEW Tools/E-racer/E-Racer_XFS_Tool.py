# -*- coding: utf-8 -*-

'''
Copyright © 2020  Bartłomiej Duda
License: GPL-3.0 License 
'''


# Program tested on Python 3.7.0
# It should be used with E-racer (PC)

# Ver    Date        Author               Comment
# v0.1   02.12.2020  Bartlomiej Duda      -

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
    Function for exporting data from XFS files
    '''    
    bd_logger("Starting export_data...")  
    
    if not os.path.exists(out_folder_path):
        os.makedirs(out_folder_path)      
    
    xfs_file = open(in_file_path, 'rb')
    xfs_size = os.path.getsize(in_file_path)
    
    xfs_file.seek(80)
    i = 0
    while 1:
        file_size = struct.unpack("<L", xfs_file.read(4))[0]
        file_type = struct.unpack("<L", xfs_file.read(4))[0]
        file_data = xfs_file.read(file_size)
        
        out_ext = ""
        if file_type == 0:
            out_ext = ".wav"
        elif file_type == 1:
            out_ext = ".ra"
        else:
            out_ext = ".bin"
            
        out_filename = "file" + str(i+1) + out_ext
        out_path = out_folder_path + out_filename
        print(out_path)
        
        out_file = open(out_path, "wb+")
        out_file.write(file_data)
        out_file.close()
        
        curr_offset = xfs_file.tell()
        i += 1
        if curr_offset == xfs_size:
            break
    
   
    
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
        #p_in_file_path = "D:\\INNE_GRY\\eRacer DEMO\\eRacer.xfs"
        #p_out_folder_path = "D:\\INNE_GRY\\eRacer DEMO\\eRacer.xfs_OUT\\"
        
        p_in_file_path = "D:\\INNE_GRY\\eRacer DEMO\\FxData\\Fxdata.xfs"
        p_out_folder_path = "D:\\INNE_GRY\\eRacer DEMO\\FxData\\Fxdata.xfs_OUT\\"
        export_data(p_in_file_path, p_out_folder_path)
        
    else:
        print("Wrong option selected!")
        
        
    
    bd_logger("End of main...")    
    
    
    
main()