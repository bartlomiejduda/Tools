# -*- coding: utf-8 -*-

# Tested on Python 3.8.0
# This tool should be used with Sonic Unleashed (Java)

# Ver    Date        Author
# v0.1   14.06.2020  Bartlomiej Duda


import os
import sys
import struct



def bd_logger(in_str):
    import datetime
    now = datetime.datetime.now()
    print(now.strftime("%d-%m-%Y %H:%M:%S") + " " + in_str)    
    


def export_data(in_DATA_path, out_FOLDER_path):
    '''
    Function for exporting data from DATA files
    '''    
    bd_logger("Starting export_data...")    
    
    DATA_file = open(in_DATA_path, 'rb')
    
    #TODO
   
    
    DATA_file.close()
    bd_logger("Ending export_data...")    
    
    
    
    
def main():
    
    main_switch = 1
    # 1 - data export 

    
  
    
    if main_switch == 1:
        p_in_DATA_path = "C:\\Users\\Arek\\Desktop\\DATA.BIN" #TODO
        p_out_FOLDER_path = "C:\\Users\\Arek\\Desktop\\DATA"
        export_data(p_in_DATA_path, p_out_FOLDER_path)
    
            
    else:
        print("Wrong option selected!")
        

    bd_logger("End of main...")    
    
    
    
main()