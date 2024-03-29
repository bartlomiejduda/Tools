# -*- coding: utf-8 -*-

'''
Copyright © 2021  Bartłomiej Duda
License: GPL-3.0 License 
'''


# Program tested on Python 3.7.0
# It should be used with Tom Clancy's Splinter Cell Conviction Mobile

# Ver    Date        Author               Comment
# v0.1   31.07.2021  Bartlomiej Duda      -
# v0.2   01.08.2021  Bartlomiej Duda      Added import function

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

def export_data(bin_file_path, off_file_path, out_file_path):
    '''
    Function for exporting texts from BIN/OFF files
    '''    
    bd_logger("Starting export_data...")  
    
    if not os.path.exists(os.path.dirname(out_file_path)):  
        os.makedirs(os.path.dirname(out_file_path))     
    
    bin_file = open(bin_file_path, 'rb')
    off_file = open(off_file_path, 'rb')
    out_file = open(out_file_path, 'wt+', encoding='utf16')
    
    num_of_texts = struct.unpack("<H", off_file.read(2))[0]
    
    off_arr = []
    off_arr.append(0)
    
    for i in range(num_of_texts):
        str_off = struct.unpack("<H", off_file.read(2))[0]
        off_arr.append(str_off)
        
    bin_size = os.path.getsize(bin_file_path)
    off_arr.append(bin_size) 
    
    for i in range(num_of_texts):
        str_off = off_arr[i]
        str_length = off_arr[i+1] - off_arr[i]
        bin_file.seek(str_off)
        str_out = "out_text" + str(i+1) + "=" + bin_file.read(str_length).decode("utf16", errors='replace').replace("\n", "\\n").rstrip("\x00")
        out_file.write(str_out + "\n")
    
    off_file.close()
    bin_file.close()
    out_file.close()
    bd_logger("Ending export_data...")    
    

def import_data(txt_file_path, bin_file_path, off_file_path):
    '''
    Function for importing texts to BIN/OFF files
    '''    
    bd_logger("Starting import_data...")  
    
    bin_file = open(bin_file_path, 'wb+')
    off_file = open(off_file_path, 'wb+')
    txt_file = open(txt_file_path, 'rt', encoding='utf16')    
    
    num_lines = 0
    str_list = []
    len_list = []
    for line in txt_file:
        num_lines += 1
        out_str = line.rstrip("\n").split("=")[1]
        str_len = len(out_str)
        str_list.append(out_str)
        len_list.append(str_len)
    
    off_file.write( struct.pack("<h", num_lines) )   
    b_off = 0
    for i in range(num_lines):
        b_str = str_list[i].replace("\\n", "\n").encode("UTF-16LE")
        str_len = len(b_str) + 4
        bin_file.write( b_str )
        bin_file.write(b"\x00\x00\x00\x00")
        
        b_off += str_len
        off_file.write( struct.pack("<h", b_off) )

    off_file.close()
    bin_file.close()
    txt_file.close()    
    bd_logger("Ending export_data...") 
    
    
    
def main():
    '''
    Main function of this program. If you are planning to use it,
    you should adjust paths first.
    '''   
    main_switch = 2
    # 1 - data export 
    # 2 - data import
    

    if main_switch == 1:
        p_bin_file_path = "C:\\Users\\Arek\\Desktop\\MAIN_EN.bin"
        p_off_file_path = "C:\\Users\\Arek\\Desktop\\MAIN_EN.off"
        p_out_file_path = "C:\\Users\\Arek\\Desktop\\out.txt"
        export_data(p_bin_file_path, p_off_file_path, p_out_file_path)
        
    if main_switch == 2:
        p_txt_file_path = "C:\\Users\\Arek\\Desktop\\out.txt"
        p_bin_file_path = "C:\\Users\\Arek\\Desktop\\MAIN_EN_new.bin"
        p_off_file_path = "C:\\Users\\Arek\\Desktop\\MAIN_EN_new.off"
        import_data(p_txt_file_path, p_bin_file_path, p_off_file_path)        
        
    else:
        bd_logger("Wrong option selected!")
        
        
    
    bd_logger("End of main...")    
    
    
    
main()