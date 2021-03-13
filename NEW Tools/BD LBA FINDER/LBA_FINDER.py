# -*- coding: utf-8 -*-

'''
Copyright © 2021  Bartłomiej Duda
License: GPL-3.0 License 
'''


# Program tested on Python 3.7.0
# It should be used with GameName (PC)

# Ver    Date        Author               Comment
# v0.1   11.03.2021  Bartlomiej Duda      -

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
    

def find_LBA(in_file_path):
    '''
    Function for finding LBA
    '''    
    bd_logger("Starting find_LBA...")  
    
        
    
    bin_file = open(in_file_path, 'rb')
    
    
    offset_list = [ 16384,   45060,    59392,    376832   ]
    size_list = [ 7205,   28338,   13547,    317175   ]
    
    
    # 1 --> little endian, side-by-side
    try:
        calc_offset = 0
        while 1:
            
            bin_file.seek(calc_offset)
            
            value1 = struct.unpack("<L", bin_file.read(4))[0]
            value2 = struct.unpack("<L", bin_file.read(4))[0]
            value3 = struct.unpack("<L", bin_file.read(4))[0]
            
            if (  (value1 == offset_list[0] and
                   value2 == offset_list[1] and 
                   value3 == offset_list[2]) or 
                  
                  (value1 == size_list[0] and
                   value2 == size_list[1] and
                   value3 == size_list[2])
               ):
                   
                bd_logger("#1 --> Match found at offset " + str(calc_offset) )
            
            calc_offset += 1
    except:
        bd_logger("#1 --> No match, " + str(calc_offset) + " iterations.")
        
        
    
    
        # 2 --> big endian, side-by-side
        try:
            calc_offset = 0
            while 1:
                
                bin_file.seek(calc_offset)
                
                value1 = struct.unpack(">L", bin_file.read(4))[0]
                value2 = struct.unpack(">L", bin_file.read(4))[0]
                value3 = struct.unpack(">L", bin_file.read(4))[0]
                
                if (  (value1 == offset_list[0] and
                   value2 == offset_list[1] and 
                   value3 == offset_list[2]) or 
                  
                  (value1 == size_list[0] and
                   value2 == size_list[1] and
                   value3 == size_list[2])
               ):
                       
                    bd_logger("#2 --> Match found at offset " + str(calc_offset) )
                
                calc_offset += 1
        except:
            bd_logger("#2 --> No match, " + str(calc_offset) + " iterations.")    
            
            
            
        # 3 --> little endian, with 4-byte space 
        try:
            calc_offset = 0
            while 1:
                
                bin_file.seek(calc_offset)
                
                value1 = struct.unpack("<L", bin_file.read(4))[0]
                bin_file.read(4)
                value2 = struct.unpack("<L", bin_file.read(4))[0]
                bin_file.read(4)
                value3 = struct.unpack("<L", bin_file.read(4))[0]
                
                if ((value1 == offset_list[0] and
                    value2 == offset_list[1] and 
                    value3 == offset_list[2]) or 
                     
                    (value1 == size_list[0] and
                    value2 == size_list[1] and
                    value3 == size_list[2])
                  ):
                       
                    bd_logger("#3 --> Match found at offset " + str(calc_offset) )
                
                calc_offset += 1
        except:
            bd_logger("#3 --> No match, " + str(calc_offset) + " iterations.")          
    
    
    
    
    
    
        # 4 --> big endian, with 4-byte space 
        try:
            calc_offset = 0
            while 1:
                
                bin_file.seek(calc_offset)
                
                value1 = struct.unpack(">L", bin_file.read(4))[0]
                bin_file.read(4)
                value2 = struct.unpack(">L", bin_file.read(4))[0]
                bin_file.read(4)
                value3 = struct.unpack(">L", bin_file.read(4))[0]
                
                if (  (value1 == offset_list[0] and
                   value2 == offset_list[1] and 
                   value3 == offset_list[2]) or 
                  
                  (value1 == size_list[0] and
                   value2 == size_list[1] and
                   value3 == size_list[2])
               ):
                       
                    bd_logger("#3 --> Match found at offset " + str(calc_offset) )
                
                calc_offset += 1
        except:
            bd_logger("#3 --> No match, " + str(calc_offset) + " iterations.")      

    
    
    
   
    
    bin_file.close()
    bd_logger("Ending find_LBA...")    
    
    
    
    
def main():
    '''
    Main function of this program. If you are planning to use it,
    you should adjust paths first.
    '''   
    main_switch = 1
    # 1 - LBA find
    

    if main_switch == 1:
        p_in_file_path = "C:\\Users\\Arek\\Desktop\\SLUS_008.87"
        find_LBA(p_in_file_path)
        
    else:
        bd_logger("Wrong option selected!")
        
        
    
    bd_logger("End of main...")    
    
    
    
main()