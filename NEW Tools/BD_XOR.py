# -*- coding: utf-8 -*-

# Tested on Python 3.8.0

# Ver    Date        Author             Comment
# v0.1   13.06.2020  Bartlomiej Duda    Initial version
# v0.2   26.11.2020  Bartlomiej Duda    Added "expected result" and "test xor"
# v0.3   25.09.2021  Bartlomiej Duda    Added multi-byte xor option



import os
import sys
import struct
import binascii


def bd_logger(in_str):
    import datetime
    now = datetime.datetime.now()
    print(now.strftime("%d-%m-%Y %H:%M:%S") + " " + in_str)    


from itertools import cycle
def xore(data, key):
    return bytes(a ^ b for a, b in zip(data, cycle(key)))



def xor_1byte_all(in_XOR_data, in_expected_result):
    '''
    Function for XORing values from 0x00 to 0xFF
    '''    
    bd_logger("Starting xor_1byte_all...")   
    
    xor_key = b'\x00'
    for i in range(255):
  
        #xoring data
        xor_res = xore(in_XOR_data, xor_key)
        if (xor_res == in_expected_result):
            print("FOUND_RES--> " + "in_xor_data: " + str(binascii.hexlify(in_XOR_data)) + " xor_res: " + str(binascii.hexlify(xor_res)) + " xor_key: " + str(binascii.hexlify(xor_key)) )
        
        #increment key
        i_xor_key = int.from_bytes(xor_key, "little")  
        i_xor_key += 1
        xor_key = struct.pack("B", i_xor_key)
    
    
    bd_logger("Ending xor_1byte_all...")    
    


def xor_multi_bytes_all(in_XOR_data, in_expected_result, in_XOR_key_MAX_length):    
    '''
    Function for XORing multi_bytes values
    '''           
    bd_logger("Starting xor_multi_bytes_all...")  
    xor_key = b'\x00'
    
    xor_range = 255 ** in_XOR_key_MAX_length
    
    print("xor_range: ", xor_range)
    
    for i in range(xor_range):
  
        #xoring data
        xor_res = xore(in_XOR_data, xor_key)
        if (xor_res == in_expected_result):
            print("FOUND_RES--> " + "in_xor_data: " + str(binascii.hexlify(in_XOR_data)) + " xor_res: " + str(binascii.hexlify(xor_res)) + " xor_key: " + str(binascii.hexlify(xor_key)) )
        
        #increment key
        i_xor_key = int.from_bytes(xor_key, "little")  
        i_xor_key += 1
        if i_xor_key <= 255:
            xor_key = struct.pack("B", i_xor_key)
        elif i_xor_key > 255 and i_xor_key <= 255 ** 2:
            xor_key = struct.pack("<H", i_xor_key)
        elif i_xor_key > 255 ** 2 and i_xor_key <= 255 ** 4:
            xor_key = struct.pack("<L", i_xor_key)
    
    
    bd_logger("Ending xor_multi_bytes_all...")      
    
    
def main():
    
    main_switch = 3
    # 1 - xor all (0-255)
    # 2 - xor test
    # 3 - xor all (multi byte XOR key)
  

    if main_switch == 1:
        xor_1byte_all(b'\x1A', b'\x20')  
        
    elif main_switch == 2:
        xor_res = xore(b'\x1A', b'\x3A')
        print(" xor_res: " + str(binascii.hexlify(xor_res)))
        
    elif main_switch == 3:
        xor_multi_bytes_all(b'\x1A', b'\x20', 2) 
        
    else:
        print("Wrong option selected!")
    
    
    bd_logger("End of main...")    
    
    
    
main()