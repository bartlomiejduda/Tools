# -*- coding: utf-8 -*-

# Tested on Python 3.8.0
# This tool should be used with Thousand arms (PSX) 

# Ver    Date        Author
# v0.1   31.08.2020  Bartlomiej Duda


import os
import sys
import struct



def bd_logger(in_str):
    import datetime
    now = datetime.datetime.now()
    print(now.strftime("%d-%m-%Y %H:%M:%S") + " " + in_str)    
    


def export_STM(p_in_file_path, out_folder_path):
    '''
    Function for exporting data from STM files
    '''    
    bd_logger("Starting export_stm...")    
    
    stm_file = open(p_in_file_path, 'rb')
    

    
    for i in range(10): #TODO
        file_name = "file" + str(i+1) + ".bin"
        
        stm_file.read(12)
        
        here = stm_file.tell()
        stm_file.read(4)
        file_size = 2020   #TODO
        #file_size = struct.unpack("<L", stm_file.read(4) )[0]
        stm_file.read(16)
        
        
        
        file_data = stm_file.read(file_size)
        
        print("file_name: " + str(file_name) + " file_size: " + str(file_size) )
        
        
        out_file = open(out_folder_path + "\\" + file_name, 'wb+')
        out_file.write(file_data)
        out_file.close()
    
    
   
    stm_file.close()
    bd_logger("Ending export_stm...")    
    
    
    
    
def main():
    
    main_switch = 1
    # 1 - bin export 
    
    if main_switch == 1:
        p_in_file_path = "C:\\Users\\Arek\\Desktop\\MAIN.STM"
        p_out_folder_path = "C:\\Users\\Arek\\Desktop\\OUT"
        export_STM(p_in_file_path, p_out_folder_path)
        
            
    else:
        print("Wrong option selected!")
        
        
    
    bd_logger("End of main...")    
    
    
    
main()