# -*- coding: utf-8 -*-

# Tested on Python 3.8.0
# This tool should be used with Silent Hill: Shattered Memories (PSP)

# Ver    Date        Author
# v0.1   05.04.2020  Bartlomiej Duda


VERSION_NUM = "v0.1"

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
    temp_arr = []
    line_flag = 0
    for i in range(count_lines):
        line = in_INI_file.readline()
        print (i)
        
        if line == '':
            break
        
        if i == 20:
            pass
        
        if (line.startswith("[") and "]" in line)   or   ("REF:" in line)    or   (line == "\n"):
            out_arr.append(line)
            #print ("temp1: " + line)

        else:
            temp_str = ""
            line2 = ""
            temp_str = line.strip("\n")
            
            wh_counter = 0
            while 1:                #     not ( (line.startswith("[") and "]" in line)   or ("REF:" in line)    or (line == "\n") ) :
                wh_counter += 1
                line = in_INI_file.readline()
                if (line.startswith("[") and "]" in line)   or   ("REF:" in line)    or   (line == "\n"):
                    #if line != "\n":
                    line2 += line
                    
                    #out_arr.append(line )
                    break
                
                
                count_lines -= 1
                #if wh_counter == 1:
                    #temp_str += line.strip("\n") + " <IKS_ENT> "
                    
                #else:
                    #temp_str += line
                    
                temp_str += line.strip("\n") + " <IKS_ENT> "    
                #print(line)
            

            temp_str += "\n"
                
            out_arr.append(temp_str)
            out_arr.append(line2 )
            #print ("temp2: " + temp_str)
     
     
     
    out_INI_file = open(out_INI_filepath, 'wt+')  
    strr_blob = ""
    for strr in out_arr:
        strr_blob += strr
    out_INI_file.write(strr_blob)
                
            
    out_INI_file.close()
    in_INI_file.close()
    bd_logger("Ending OmegaT fix...")


#OmegaT fix
p_in_INI_filepath = "c:\\Users\\Arek\\Spolszczenia\\Silent Hill Shattered Memories\\target\\PSP_USA\\2C238264.ini"
p_out_INI_filepath = "c:\\Users\\Arek\\Spolszczenia\\Silent Hill Shattered Memories\\target\\PSP_USA\\2C238264_fixed.ini"
fix_INI_file(p_in_INI_filepath, p_out_INI_filepath)