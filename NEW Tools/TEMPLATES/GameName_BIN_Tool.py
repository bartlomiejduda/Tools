# -*- coding: utf-8 -*-

# Tested on Python 3.8.0
# This tool should be used with GameName (Java)

# Ver    Date        Author
# v0.1   17.04.2020  Bartlomiej Duda

import os
import sys
import struct



def bd_logger(in_str):
    import datetime
    now = datetime.datetime.now()
    print(now.strftime("%d-%m-%Y %H:%M:%S") + " " + in_str)    
    

def export_data(in_file_path, out_folder_path):
    '''
    Function for exporting data from BIN files
    '''    
    bd_logger("Starting export_data...")  
    
    if not os.path.exists(out_folder_path):
        os.makedirs(out_folder_path)      
    
    bin_file = open(in_file_path, 'rb')
    
   
    
    bin_file.close()
    bd_logger("Ending export_data...")    
    
    
    
    
def main():
    
    main_switch = 1
    # 1 - data export 
    

    if main_switch == 1:
        p_in_file_path = "C:\\Users\\Arek\\Desktop\\Silent_Hill_Orphan_SPOL\\JAR_out\\chunks\\0.bin"
        p_out_folder_path = "C:\\Users\\Arek\\Desktop\\Silent_Hill_Orphan_SPOL\\JAR_out\\chunks\\0.bin_out"
        export_data(p_in_file_path, p_out_folder_path)
        
    else:
        print("Wrong option selected!")
        
        
    
    bd_logger("End of main...")    
    
    
    
main()