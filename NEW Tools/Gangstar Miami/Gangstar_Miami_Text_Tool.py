# -*- coding: utf-8 -*-

'''
Copyright © 2021  Bartłomiej Duda
License: GPL-3.0 License 
'''


# Program tested on Python 3.7.0
# It should be used with Gangstar Miami (Android)

# Ver    Date        Author               Comment
# v0.1   28.05.2021  Bartlomiej Duda      -

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
    

def export_text(in_file_path, out_file_path):
    '''
    Function for exporting text
    '''    
    bd_logger("Starting export_text...")  
    
    if not os.path.exists(os.path.dirname(out_file_path)):  
        os.makedirs(os.path.dirname(out_file_path))     
    
    in_file = open(in_file_path, 'rb')
    out_file = open(out_file_path, 'wt+')
    
    num_of_lines = struct.unpack("<H", in_file.read(2))[0]
    
    for i in range(num_of_lines):
        s_len = struct.unpack("<H", in_file.read(2))[0]
        s_text = in_file.read(s_len).decode("utf8").replace("\n", "\\n").replace("\r", "\\r")
        out_file.write(s_text + "\n")
    
    in_file.close()
    out_file.close()
    bd_logger("Ending export_text...")    


def import_text(in_file_path, out_file_path):
    '''
    Function for importing text
    '''    
    bd_logger("Starting import_text...")  
    
    if not os.path.exists(os.path.dirname(out_file_path)):  
        os.makedirs(os.path.dirname(out_file_path))     
    
    in_file = open(in_file_path, 'rt')
    out_file = open(out_file_path, 'wb+')   
    
    line_list = []
    line_count = 0
    for line in in_file:
        line_count += 1
        line_list.append( line.rstrip("\n") )
        
     
    num_of_lines = struct.pack("<H", line_count)   
    out_file.write(num_of_lines)
    
    for new_line in line_list:
        
        b_str = new_line.replace("\\n", "\n").replace("\\r", "\r").encode("utf8")
        l_len = len(b_str)
        bl_len = struct.pack("<H", l_len)        
        
        out_file.write(bl_len)
        out_file.write(b_str)
    
    bd_logger("Ending import_text...")  
    
    
    
    
def main():
    '''
    Main function of this program. If you are planning to use it,
    you should adjust paths first.
    '''   
    main_switch = 1
    # 1 - text export 
    # 2 - text import
    

    p_lang_file_path = "C:\\Users\\Arek\\Desktop\\ch1.english"
    p_txt_file_path = "C:\\Users\\Arek\\Desktop\\ch1.txt"
    
    if main_switch == 1:
        export_text(p_lang_file_path, p_txt_file_path)
        
    elif main_switch == 2:
        import_text(p_txt_file_path, p_lang_file_path)    
        
    else:
        bd_logger("Wrong option selected!")
        
        
    
    bd_logger("End of main...")    
    
    
    
main()


