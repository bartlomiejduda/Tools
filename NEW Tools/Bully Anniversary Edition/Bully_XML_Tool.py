# -*- coding: utf-8 -*-

'''
Copyright © 2020  Bartłomiej Duda
License: GPL-3.0 License 
'''


# Program tested on Python 3.7.0
# It should be used with Bully

# Ver    Date        Author               Comment
# v0.1   15.12.2020  Bartlomiej Duda      -

import os
import sys
import struct
import datetime
#from ctypes import c_char, c_char_p
import ctypes


def bd_logger(in_str):
    '''
    Function for logging debug messages
    '''   
    now = datetime.datetime.now()
    print(now.strftime("%d-%m-%Y %H:%M:%S") + " " + in_str)    
    

def decode_data(in_file_path, out_file_path):
    '''
    Function for decoding XML files
    '''    
    bd_logger("Starting decode_data...")  
    
    encryption_key = "6Ev2GlK1sWoCa5MfQ0pj43DH8Rzi9UnX"
    magichash = 0xCEB538D
    stringDecode_buffer = []
    
    xml_file = open(in_file_path, 'rb')
    
    
    # INIT STRING
    for i in range(256):
        stringDecode_buffer.append(0)
     
    index = 0 
    while 1:
        stringDecode_buffer[ord(encryption_key[index])] = index
        index += 1
        if index == 32:
            break
        
        
    # DECODE 1
    s = 0
    index = 0
    counter = 0
    v1 : c_char = -1
    
    encoded_data = xml_file.read()
    l = len(encoded_data) - 2
    buffer_len = l
    decoded_data_size = (5 * l >> 3)
    
    decoded_data = []
    for i in range(decoded_data_size+1):
        decoded_data.append(0)
    
    while 1:
        if l <= counter:
            buffer_len = 0
        else:
            buffer_len = encoded_data[counter+2]
        
        dectable = stringDecode_buffer[buffer_len]
        
        
        dec_flag = -1
         
        if s == 0:
            v1 = 0
            dectable = 8 * dectable    
            dec_flag = 0
            
        elif s == 1:
            v1 = 0
            dectable = 4 * dectable  
            dec_flag = 1
            
        elif s == 2:
            v1 = 0
            dectable = 2 * dectable 
            dec_flag = 2
            
        elif s == 3:
            v1 = 0
            dec_flag = 3
            
        elif s == 4:
            v1 = (dectable << 7) & 0xFF
            dectable >>= 1
            dec_flag = 4
            
        elif s == 5:
            v1 = (dectable << 6) & 0xFF  
            dectable >>= 2  
            dec_flag = 5
            
        elif s == 6:
            v1 = (32 * dectable) & 0xFF  
            dectable >>= 3   
            dec_flag = 6
            
        elif s == 7:
            v1 = (16 * dectable) & 0xFF
            dectable >>= 4
            dec_flag = 7
        
        else:
            v1 = 0
            dectable = 0
            dec_flag = 999
            
        decoded_data[index] |= dectable 
        
        
        if l - 1 != index:
            decoded_data[index+1] |= v1
            
        if (s+5) <= 7:
            s += 5
        else:
            index += 1
            s -= 3
            if index == l:
                return
            
        counter += 1
        
        if l <= counter:
            break
            

    
    
    # DECODE 2
    num = 0x12
    for i in range(decoded_data_size):
        ch = decoded_data[i]
        #magichash = magichash % 0xFFFFFFFF
        magichash = (0xAB * (magichash % 0xB1) - 2 * (magichash // 0xB1)) 
        char_out = abs((ch ^ num) + magichash) % 0xFF
        decoded_data[i] = char_out
        num += 6
    
    
    print(decoded_data)
    
    out_file = open(out_file_path, "wb+")
    
    for byte in decoded_data[:-1]:
        #print(byte)
        #out_file.write(struct.pack("B", byte))
        pass
        
    out_file.close()
   
   
    
    xml_file.close()
    bd_logger("Ending export_data...")    
    
    
    
    
def main():
    '''
    Main function of this program. If you are planning to use it,
    you should adjust paths first.
    '''   
    main_switch = 1
    # 1 - data decode 
    

    if main_switch == 1:
        p_in_file_path = "C:\\Users\\Arek\\Desktop\\input.xml"
        p_out_file_path = "C:\\Users\\Arek\\Desktop\\output_py.txt"
        decode_data(p_in_file_path, p_out_file_path)
        
    else:
        print("Wrong option selected!")
        
        
    
    bd_logger("End of main...")    
    
    
    
main()