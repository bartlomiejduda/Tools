# -*- coding: utf-8 -*-

# Tested on Python 3.7.3
# This tool should be used with Crash Mutant Island 2008 Java game

# Ver    Date        Name
# v1.0   09.10.2019  Bartlomiej Duda


VERSION_NUM = "v1.00"


import os
import sys
import struct



def open_text():
    print ("Starting Crash Java text load...")
    
    p_input_textfile_path = "C:\\Users\\Adam\\Desktop\\Txts_Pack_nb_0"
    text_file = open(p_input_textfile_path, 'rb')    
    
    text_file.read(16)
    
    i = 0
    while 1:
        i += 1
        curr_offset = text_file.tell()
        string_size = struct.unpack('>H', text_file.read(2))[0]
        #text_string = struct.unpack(str(string_size) + "s", text_file.read(string_size))[0]
        text_file.read(string_size)
        
        print("i=" + str(i) + " string_size = " + str(string_size) + " curr_offset = " + str(curr_offset) )
        
    text_file.close()
    
    
open_text()