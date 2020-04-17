# -*- coding: utf-8 -*-

# Tested on Python 3.8.0
# This tool should be used with Silent Hill: Shattered Memories (PSP)

# Ver    Date        Author
# v0.1   11.04.2020  Bartlomiej Duda
# v0.2   12.04.2020  Bartlomiej Duda
# v0.3   16.04.2020  Bartlomiej Duda



VERSION_NUM = "v0.3"

import os
import sys
import struct
import zlib



def bd_logger(in_str):
    import datetime
    now = datetime.datetime.now()
    print(now.strftime("%d-%m-%Y %H:%M:%S") + " " + in_str)    
    
    
def unzlib_file(in_filepath, out_filepath):
    '''
    Function for uncompressing input files
    '''    
    bd_logger("Starting unzlib...")
    
    in_file = open(in_filepath, 'rb')
    out_file = open(out_filepath, 'wb+')   
    
    data = in_file.read()
    uncomp_data = zlib.decompress(data)    
    out_file.write(uncomp_data)
    
    in_file.close()
    out_file.close()
    
    bd_logger("Ending unzlib...")
    
    
def zlib_file(in_filepath, out_filepath):
    '''
    Function for compressing input files
    '''
    bd_logger("Starting zlib...")
    
    in_file = open(in_filepath, 'rb')
    out_file = open(out_filepath, 'wb+')   
    
    data = in_file.read()
    compressed_data = zlib.compress(data, 9)  
    out_file.write(compressed_data)
    
    in_file.close()
    out_file.close()
    
    bd_logger("Ending zlib...")    
    

def main():
  
    main_switch = 2
    # 1 - zlib text
    # 2 - unzlib images 
    # 3 - zlib images
    

    if main_switch == 1:
        p_in_filepath = "C:\\Users\\Arek\\Desktop\\Silent_Hill_SM_Tools_v7\\TextConv\\IN\\2C238264"
        p_out_filepath = "C:\\Users\\Arek\\Desktop\\Silent_Hill_SM\\USA_ROM\\data_arc_test\\DATA_1316_222"
        zlib_file(p_in_filepath, p_out_filepath)
        
    elif main_switch == 2:
        p_in_filepath = "C:\\Users\\Arek\\Desktop\\Silent_Hill_SM\\USA_ROM\\data_arc_test\\DATA_1735"
        p_out_filepath = "C:\\Users\\Arek\\Desktop\\Silent_Hill_SM\\USA_ROM\\data_arc_test\\DATA_1735_unzlib.jpeg"
        unzlib_file(p_in_filepath, p_out_filepath) 
        
        p_in_filepath = "C:\\Users\\Arek\\Desktop\\Silent_Hill_SM\\USA_ROM\\data_arc_test\\DATA_1783"
        p_out_filepath = "C:\\Users\\Arek\\Desktop\\Silent_Hill_SM\\USA_ROM\\data_arc_test\\DATA_1783_unzlib.jpeg"
        unzlib_file(p_in_filepath, p_out_filepath)   
        
    elif main_switch == 3:
        p_in_filepath = "C:\\Users\\Arek\\Desktop\\Silent_Hill_SM\\USA_ROM\\data_arc_test\\DATA_1735_unzlib.jpeg"
        p_out_filepath = "C:\\Users\\Arek\\Desktop\\Silent_Hill_SM\\USA_ROM\\data_arc_test\\DATA_1735_zlib"
        zlib_file(p_in_filepath, p_out_filepath) 
        
        p_in_filepath = "C:\\Users\\Arek\\Desktop\\Silent_Hill_SM\\USA_ROM\\data_arc_test\\DATA_1783_unzlib.jpeg"
        p_out_filepath = "C:\\Users\\Arek\\Desktop\\Silent_Hill_SM\\USA_ROM\\data_arc_test\\DATA_1783_zlib"
        zlib_file(p_in_filepath, p_out_filepath)           
        
        
    else:
        print("Wrong main switch option selected!")
        
    bd_logger("End of main...")
    
    
    
main()