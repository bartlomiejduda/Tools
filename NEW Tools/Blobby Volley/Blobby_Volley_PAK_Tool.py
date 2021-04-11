# -*- coding: utf-8 -*-

'''
Copyright © 2021  Bartłomiej Duda
License: GPL-3.0 License 
'''


# Program tested on Python 3.7.0
# It should be used with Blobby Volley 1.8 (PC)

# Ver    Date        Author               Comment
# v0.1   11.04.2021  Bartlomiej Duda      -

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


FLAG_1 = 0
COUNTER_1 = 0
CURR_SIZE_1 = 256

def read_file_3(in_pak_file):
    global FLAG_1
    global COUNTER_1
    global CURR_SIZE_1
    if (FLAG_1 == 1): # line 8
        in_pak_file.seek( in_pak_file.tell() - 3)
        b3 = int.from_bytes(in_pak_file.read(3), "little")
        calc_b3 = (b3 >> 0x0C) & 0x0FFF
        FLAG_1 = 0
        
        if calc_b3 == 4095: # line 17
            pass #TODO
        
    else:
        
        if CURR_SIZE_1 == 256:  # line 29
            CURR_SIZE_1 = 0
            
        CURR_SIZE_1 += 1    
        b3 = int.from_bytes(in_pak_file.read(3), "little")
        calc_b3 = b3 & 0x0FFF
        FLAG_1 = 1
        
        if calc_b3 == 4095: #line 53
            pass # TODO 
        
    return calc_b3

decode_list = []
def get_from_decode_list(in_byte):
    if in_byte <= 255:
        return in_byte
    else:
        return decode_list[-7]


def create_string():
    if b3_original <= 255: # line 7
        pass #TODO
        

def export_data(in_file_path, out_folder_path):
    '''
    Function for exporting data from PAK files
    '''    
    bd_logger("Starting export_data...")  
    
    if not os.path.exists(os.path.dirname(out_folder_path)):  
        os.makedirs(os.path.dirname(out_folder_path))     
    
    pak_file = open(in_file_path, 'rb')
    
    out_b = b''
    v2 = 256
    
    b3_decoded = read_file_3(pak_file)
    b3_original = b3_decoded
    
    if b3_decoded != 4095:
        for i in range(100):  # line 24
        
            b3_decoded = read_file_3(pak_file)
            counter_v5 = b3_decoded
            
            if b3_original == 4094: # line 32
                v2 = 256
            else:
                if b3_decoded != 4095:
                    decode_list.append(b3_original)
                    #b3_decoded = get_from_decode_list(b3_decoded)   # TODO
                    
                    if b3_decoded <= 255:
                        pass
                    else:
                        decode_list.append(decode_list[-7])
                        decode_list.append(decode_list[-6])
                    

                if b3_original <= 255:
                    b_1 = (b3_original).to_bytes(1, byteorder='little')
                else:
                    b_1 = b''
                    #b_1 += (decode_list[-10]).to_bytes(1, byteorder='little')
                    #b_1 += (decode_list[-9]).to_bytes(1, byteorder='little')
                    b_1 = b'\x0D\x0A' #temp workaround...

                out_b += b_1
                print(out_b)
            
            b3_original = b3_decoded    # counter was here
            
            if counter_v5 == 4095:
                break
     
    #print(   out_list)    
    print(decode_list)
        
     
    
    pak_file.close()
    bd_logger("Ending export_data...")    
    
    
    
    
def main():
    '''
    Main function of this program. If you are planning to use it,
    you should adjust paths first.
    '''   
    main_switch = 1
    # 1 - data export 
    

    if main_switch == 1:
        p_in_file_path = "C:\\Users\\Arek\\Desktop\\blobbyvolley_1.8\\text.pak"
        p_out_folder_path = "C:\\Users\\Arek\\Desktop\\blobbyvolley_1.8\\text.pak_OUT\\"
        export_data(p_in_file_path, p_out_folder_path)
        
    else:
        bd_logger("Wrong option selected!")
        
        
    
    bd_logger("End of main...")    
    
    
    
main()