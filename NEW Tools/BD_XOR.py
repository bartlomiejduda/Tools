# -*- coding: utf-8 -*-

# Tested on Python 3.8.0

# Ver    Date        Author             Comment
# v0.1   13.06.2020  Bartlomiej Duda    Initial version
# v0.2   26.11.2020  Bartlomiej Duda    Added "expected result" and "test xor"



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
    bd_logger("Starting xor_all...")   
    
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
    
    
    bd_logger("Ending xor_all...")    
    
    
        
    
    
    
def main():
    
    main_switch = 1
    # 1 - xor all (0-255)
    # 2 - xor test
  

    if main_switch == 1:
        xor_1byte_all(b'\x1A', b'\x20')  
        
    elif main_switch == 2:
        xor_res = xore(b'\x1A', b'\x3A')
        print(" xor_res: " + str(binascii.hexlify(xor_res)))
        
    else:
        print("Wrong option selected!")
    
    
    bd_logger("End of main...")    
    
    
    
main()