# -*- coding: utf-8 -*-

# Tested on Python 3.8.0
# This tool should be used with Homefront

# Ver    Date        Author
# v0.1   11.06.2020  Bartlomiej Duda
# v0.2   11.06.2020  Bartlomiej Duda



import os
import sys
import struct



def bd_logger(in_str):
    import datetime
    now = datetime.datetime.now()
    print(now.strftime("%d-%m-%Y %H:%M:%S") + " " + in_str)    
    


from itertools import cycle
def xore(data, key):
    return bytes(a ^ b for a, b in zip(data, cycle(key)))


def convert_text(in_TEXT_path, out_TEXT_path):
    '''
    Function for converting text from Homefront
    '''    
    bd_logger("Starting convert_text...")    
    
    in_file = open(in_TEXT_path, 'rb')
    out_file = open(out_TEXT_path, 'wt+', encoding="utf8")
    
    
    i = 0
    while 1:
        i += 1
        back_offset = in_file.tell()  
        try:
            str_len = struct.unpack('<l', xore(in_file.read(4), b'\xFF'))[0] * 2
        except:
            bd_logger("End of file. Exiting loop.")
            break
        
        if str_len <= 0:
            in_file.seek(back_offset)
            val1_offset = in_file.tell() 
            val1 = struct.unpack('<l', in_file.read(4))[0]
            str_len = struct.unpack('<l', xore(in_file.read(4), b'\xFF'))[0] * 2
            #print( str(i) + ") " + "val1_offset: " + str(val1_offset) + " val1: " + str(val1) )
        
        curr_offset = in_file.tell()    
        b_str = in_file.read(str_len)
        null = in_file.read(2)
        s_str = b_str.decode("utf16")
        #print( str(i) + ") " + "curr_offset: " + str(curr_offset) )
        out_file.write(s_str + "\n")
    
    
    
    in_file.close()
    out_file.close()
    bd_logger("Ending convert_text...")    
    
    
        
    
    
    
def main():
    
    main_switch = 1
    # 1 - text export 
  

    if main_switch == 1:
        in_filepath = "C:\\Users\\Arek\\Desktop\\Homefront Loc\\Coalesced_int.bin"
        out_ini_path = "C:\\Users\\Arek\\Desktop\\Homefront Loc\\Coalesced_int.bin_OUT.ini"
        convert_text(in_filepath, out_ini_path)
        
        in_filepath = "C:\\Users\\Arek\\Desktop\\Homefront Loc\\Coalesced_int_full.bin"
        out_ini_path = "C:\\Users\\Arek\\Desktop\\Homefront Loc\\Coalesced_int_full.bin_OUT.ini"
        convert_text(in_filepath, out_ini_path)        
        
        
    else:
        print("Wrong option selected!")
    
    
    bd_logger("End of main...")    
    
    
    
main()