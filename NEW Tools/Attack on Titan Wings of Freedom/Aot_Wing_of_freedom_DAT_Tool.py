# -*- coding: utf-8 -*-

'''
Copyright © 2021  Bartłomiej Duda
License: GPL-3.0 License 
'''


# Program tested on Python 3.7.0
# It should be used with Attack on Titan: Wings of Freedom

# Ver    Date        Author               Comment
# v0.1   30.10.2021  Bartlomiej Duda      -

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
    Function for exporting data from DAT files
    '''    
    bd_logger("Starting export_data...")  
    
    if not os.path.exists(os.path.dirname(out_file_path)):  
        os.makedirs(os.path.dirname(out_file_path))     
    
    dat_file = open(in_file_path, 'rb')
    ini_file = open(out_file_path, 'wt+', encoding='utf8')
    
    num_of_texts = struct.unpack("<L", dat_file.read(4))[0]
    
    for i in range(num_of_texts):
        text_offset = struct.unpack("<L", dat_file.read(4))[0]
        text_length = struct.unpack("<L", dat_file.read(4))[0]
        
        back_offset = dat_file.tell()
        
        dat_file.seek(text_offset)
        text_str = dat_file.read(text_length-1).decode("utf8").replace("\n", "\\n")
        dat_file.seek(back_offset)
        ini_file.write("text_to_translate" + str(i+1) + "=" + text_str + "\n")
    
    dat_file.close()
    ini_file.close()
    bd_logger("Ending export_data...")    
    
 
def import_data(in_file_path, out_file_path):
    '''
    Function for importing data to DAT files
    '''    
    bd_logger("Starting import_data...")  
    
    if not os.path.exists(os.path.dirname(out_file_path)):  
        os.makedirs(os.path.dirname(out_file_path))     
    
    ini_file = open(in_file_path, 'rt', encoding='utf8')
    dat_file = open(out_file_path, 'wb+')
    
    num_of_texts = 0
    str_arr = []
    len_arr = []
    for line in ini_file:
        num_of_texts += 1
        text_str = (line.split("=")[-1].strip("\n").replace("\\n", "\n") + "\x00").encode('utf8')
        text_length = len(text_str)
        str_arr.append(text_str)
        len_arr.append(text_length)
        
        
    base_offset = (num_of_texts * 8) + 4
    dat_file.write(struct.pack("<L", num_of_texts))
    
    text_offset = base_offset
    for i in range(num_of_texts):
        dat_file.write(struct.pack("<L", text_offset))
        dat_file.write(struct.pack("<L", len_arr[i]))
        text_offset += len_arr[i]
        
    for i in range(num_of_texts):
        dat_file.write(str_arr[i])
                               
    
    
    
    dat_file.close()
    ini_file.close()
    bd_logger("Ending import_data...")    
 
    
    
    
def main():
    '''
    Main function of this program. If you are planning to use it,
    you should adjust paths first.
    '''   
    main_switch = 1
    # 1 - data export 
    # 2 - data import
    

    if main_switch == 1:
        p_in_file_path = "C:\\Users\\Arek\\Desktop\\AOT\\000013f6.dat"
        p_out_file_path = "C:\\Users\\Arek\\Desktop\\AOT\\000013f6.ini"
        export_data(p_in_file_path, p_out_file_path)
        
    elif main_switch == 2:
        p_in_file_path = "C:\\Users\\Arek\\Desktop\\AOT\\000013f6.ini"
        p_out_file_path = "C:\\Users\\Arek\\Desktop\\AOT\\000013f6_NEW.dat"
        import_data(p_in_file_path, p_out_file_path)    
        
    else:
        bd_logger("Wrong option selected!")
        
        
    
    bd_logger("End of main...")    
    
    
    
main()