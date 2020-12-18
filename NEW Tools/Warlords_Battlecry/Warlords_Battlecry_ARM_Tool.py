# -*- coding: utf-8 -*-

'''
Copyright © 2020  Bartłomiej Duda
License: GPL-3.0 License 
'''


# Program tested on Python 3.7.0
# It should be used with Warlords Battlecry

# Ver    Date        Author               Comment
# v0.1   18.12.2020  Bartlomiej Duda      -

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
    

def decrypt_data(in_file_path, out_file_path):
    '''
    Function for decrypting data from ARM files
    '''    
    bd_logger("Starting decrypt_data...")  
       
    
    arm_file = open(in_file_path, 'rb')
    key_file = open("key.bin", 'rb')
    out_file = open(out_file_path, 'wb+')
    
    arm_size = os.path.getsize(in_file_path)
    
    for i in range(arm_size):
        arm_byte = struct.unpack("B", arm_file.read(1))[0]
        key_file.seek(arm_byte)
        out_byte = key_file.read(1)
        out_file.write(out_byte)
        
    
    arm_file.close()
    key_file.close()
    out_file.close()
    bd_logger("Ending decrypt_data...")    
    
    
    
    
def main():
    '''
    Main function of this program. If you are planning to use it,
    you should adjust paths first.
    '''   
    main_switch = 1
    # 1 - data decryption
    

    if main_switch == 1:
        p_in_file_path = "C:\\Users\\Arek\\Desktop\\Titan.ARM"
        p_out_file_path = "C:\\Users\\Arek\\Desktop\\Titan.ARM_decrypted"
        decrypt_data(p_in_file_path, p_out_file_path)
        
    else:
        print("Wrong option selected!")
        
        
    
    bd_logger("End of main...")    
    
    
    
main()