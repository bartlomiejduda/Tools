# -*- coding: utf-8 -*-

# Tested on Python 3.8.0
# This tool should be used with Silent Hill: Shattered Memories (PSP)

# Ver    Date        Author
# v0.1   05.04.2020  Bartlomiej Duda
# v0.2   06.04.2020  Bartlomiej Duda


VERSION_NUM = "v0.2"

import os
import sys
import struct



def bd_logger(in_str):
    import datetime
    now = datetime.datetime.now()
    print(now.strftime("%d-%m-%Y %H:%M:%S") + " " + in_str)    
    
    

def fix_INI_file(in_INI_filepath, out_INI_filepath):
    bd_logger("Starting OmegaT fix...")
    
    count_lines = len(open( in_INI_filepath).readlines() )
    print("Line count: " + str(count_lines))
    
    in_INI_file = open(in_INI_filepath, 'rt')
    
    
    out_arr = []
    for i in range(count_lines):
        line = in_INI_file.readline()
        print (i)
        
        if line == '':
            break
        
        if ((line.startswith("[") and "]" in line)   or   ("REF:" in line)    or   (line == "\n") 
            or   (line.startswith("<c=1>"))  
            or   (line.startswith("<c=2>")) 
            or   (line.startswith("<c=3>"))  
            or   (line.startswith("<b=9>"))  
            
            ):   
            pass
        else:
            line = "BD_TRANSLATE_TEXT=" + line
            
        out_arr.append(line)
     
     
    out_INI_file = open(out_INI_filepath, 'wt+')  

    for line in out_arr:
        out_INI_file.write(line)
                
            
    out_INI_file.close()
    in_INI_file.close()
    bd_logger("Ending OmegaT fix...")


#OmegaT fix
p_in_INI_filepath = "c:\\Users\\Arek\\Spolszczenia\\Silent Hill Shattered Memories\\source\\PSP_USA\\2C238264.ini"
p_out_INI_filepath = "c:\\Users\\Arek\\Spolszczenia\\Silent Hill Shattered Memories\\source\\PSP_USA\\2C238264_fixed.ini"
fix_INI_file(p_in_INI_filepath, p_out_INI_filepath)