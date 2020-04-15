# -*- coding: utf-8 -*-

# Tested on Python 3.8.0
# This tool should be used with Silent Hill: Shattered Memories (PSP)

# Ver    Date        Author
# v0.1   05.04.2020  Bartlomiej Duda
# v0.2   06.04.2020  Bartlomiej Duda
# v0.3   07.04.2020  Bartlomiej Duda
# v0.4   09.04.2020  Bartlomiej Duda


VERSION_NUM = "v0.4"

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
        print ("Line: " + str(i+1))
        
        if line == '':
            break
        
        if ((line.startswith("[") and "]" in line)   or   ("REF:" in line)    or   (line == "\n") 
            or   (line.startswith("<c="))  
            or   (line.startswith("<b="))   
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


def restore_INI_file(in_INI_filepath, out_INI_filepath):
    bd_logger("Starting OmegaT restore...")
    
    in_INI_file = open(in_INI_filepath, 'rt', encoding="utf8")
    out_INI_file = open(out_INI_filepath, 'wt+', encoding="utf8")
    
    i = 0
    for line in in_INI_file:
        i += 1
        line = line.replace("BD_TRANSLATE_TEXT=", "")
        
        if i > 12660:
            line = line.replace("<c=1> a", "<c=1>")  #fix for debug mode
        
        
        out_INI_file.write(line)
        
    in_INI_file.close()
    out_INI_file.close()
    
    bd_logger("Ending OmegaT restore...")



def main():
    
    main_switch = 2
    # 1 - fixing INI
    # 2 - restore INI
    
    
    ini_arr = [ "2C238264.ini", "2C238276.ini", "7EFCA512.ini" ]
    ini_fixed_arr = [ "2C238264_fixed.ini", "2C238276_fixed.ini", "7EFCA512_fixed.ini" ]
    ini_out_arr = [ "2C238264_fixed_out.ini", "2C238276_fixed_out.ini", "7EFCA512_fixed_out.ini" ]
    ini_path = "c:\\Users\\Arek\\Spolszczenia\\Silent Hill Shattered Memories\\target\\PSP_USA\\"    
    
    if main_switch == 1:
        i = 0
        for item in ini_arr:
            ini_in = ini_path + item 
            ini_out = ini_path + ini_fixed_arr[i]
            fix_INI_file(ini_in, ini_out)
            i += 1
            
    elif main_switch == 2:
        i = 0
        for item in ini_fixed_arr:
            ini_in = ini_path + item
            ini_out = ini_path + ini_out_arr[i]
            restore_INI_file(ini_in, ini_out)
            i += 1
    
    else:
        print("Invalid switch option!")
        
        
    bd_logger("End of main...")
    
    
    
main()