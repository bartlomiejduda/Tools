# -*- coding: utf-8 -*-

'''
Copyright © 2021  Bartłomiej Duda
License: GPL-3.0 License 
'''


# Program tested on Python 3.7.0
# It should be used with games from 10tons

# Ver    Date        Author               Comment
# v0.1   23.07.2021  Bartlomiej Duda      -

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
    

def export_data(in_file_path, out_file_path):
    '''
    Function for decrypting XML files from 10tons games
    '''    
    bd_logger("Starting export_data...")  
    
    if not os.path.exists(os.path.dirname(out_file_path)):  
        os.makedirs(os.path.dirname(out_file_path))     
    
    in_file = open(in_file_path, 'rb')
    
    SIGN_CONST = "10TONS_SECRET\x00"
    
    f_sign = in_file.read(14).decode("utf8")
    
    if f_sign != SIGN_CONST:
        bd_logger("It is not 10tons XML file! Exiting!")
        return
    
    f_data_size = struct.unpack( "<L", in_file.read(4))[0]
    f_check_value = in_file.read(4)
    
    back_offset = in_file.tell()
    enc_data = in_file.read(f_data_size)
    
    # here starts decoding part
    dec_data = ""
    check_value = 0
    for i in range(f_data_size):
        dec_char = ( i  + enc_data[i]  + ord(SIGN_CONST[i % 13]) ) & 0xFF
        dec_data += chr(dec_char) 
        check_value += (i * (enc_data[i])) #TODO
        

    # saving decoded data 
    out_file = open(out_file_path, "wt+")
    out_file.write(dec_data)
    out_file.close()
    

    
    in_file.close()
    bd_logger("Ending export_data...")    
    
    
    
    
def main():
    '''
    Main function of this program. If you are planning to use it,
    you should adjust paths first.
    '''   
    main_switch = 1
    # 1 - data export 
    

    if main_switch == 1:
        p_in_file_path = "C:\\Users\\Arek\\Desktop\\0.xml"
        p_out_file_path = "C:\\Users\\Arek\\Desktop\\out.xml"
        export_data(p_in_file_path, p_out_file_path)
        
    else:
        bd_logger("Wrong option selected!")
        
        
    
    bd_logger("End of main...")    
    
    
    
main()