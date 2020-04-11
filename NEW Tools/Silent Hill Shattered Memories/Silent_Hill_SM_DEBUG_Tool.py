# -*- coding: utf-8 -*-

# Tested on Python 3.8.0
# This tool should be used with Silent Hill: Shattered Memories (PSP)

# Ver    Date        Author
# v0.1   11.04.2020  Bartlomiej Duda



VERSION_NUM = "v0.1"

import os
import sys
import struct
import zlib



def bd_logger(in_str):
    import datetime
    now = datetime.datetime.now()
    print(now.strftime("%d-%m-%Y %H:%M:%S") + " " + in_str)    
    
    

def debug_INI_file(in_INI_filepath, out_INI_filepath):
    bd_logger("Starting debug...")
    

    in_INI_file = open(in_INI_filepath, 'rt', encoding="utf8")
    out_INI_file = open(out_INI_filepath, 'wt+', encoding="utf8")  
    
    f_size = os.path.getsize(in_INI_filepath)
    f_size2 = os.path.getsize(out_INI_filepath)
    diff = f_size2 - f_size
    print("f_size: " + str(f_size) )    

    i = 0
    for line in in_INI_file:
        i += 1
        print(i)
        if len(line) > 105 and line.startswith("<c="):
            if not line[0:105].endswith("\n"):
                line = line[0:105] + "\n"  #debug1
            else:
                line = line[0:105]
        
        
        
        #if line.startswith("<c="):    
            #line = (line.replace("S", "a").replace("T", "b").replace("A", "c")
                        #.replace("R", "d").replace("G", "e").replace("M", "f")
                        #.replace("E", "g").replace("a", "T").replace("e", "U").replace("i", "V").replace("O", "x")      ) #debug2
            
            
            
            
        #if line.startswith("<c="):    
            #line = (line.replace("S", "À").replace("T", "Ü").replace("A", "Ö")
                        #.replace("R", "É").replace("G", "ü").replace("M", "ö")
                        #.replace("E", "é").replace("a", "á").replace("e", "â").replace("i", "ä").replace("O", "ñ")      ) #debug3            
        
        
        
        
        
        out_INI_file.write(line)
                
            
    out_INI_file.close()
    in_INI_file.close()
    bd_logger("Ending debug...")



def INI_padding(in_INI_filepath, out_INI_filepath):
    bd_logger("Starting padding...")
    
    in_INI_file = open(in_INI_filepath, 'rt', encoding="utf8")
    out_INI_file = open(out_INI_filepath, 'wt+', encoding="utf8")  
    
    oryg_ini_size = 287796
    f_size = os.path.getsize(in_INI_filepath)
    diff = oryg_ini_size - f_size
    print("Diff: " + str(diff) )    
    
    for line in in_INI_file:
        if diff > 5 and line.startswith("<c="):
            line = line.replace("\n", "") + "     " + "\n"
            diff -= 5

        out_INI_file.write(line)
                             
    out_INI_file.close()
    in_INI_file.close()
    print("in: " + in_INI_filepath)
    print("out: " + out_INI_filepath)
    bd_logger("Ending padding...")    


    
def unzlib_file(in_filepath, out_filepath):
    bd_logger("Starting unzlib...")
    
    in_file = open(in_filepath, 'rb')
    out_file = open(out_filepath, 'wb+')   
    
    data = in_file.read()
    uncomp_data = zlib.decompress(data)    
    out_file.write(uncomp_data)
    
    in_file.close()
    out_file.close()
    
    bd_logger("Ending unzlib...")
    
    
def zlib_file(in_filepath, out_filepath):
    bd_logger("Starting zlib...")
    
    in_file = open(in_filepath, 'rb')
    out_file = open(out_filepath, 'wb+')   
    
    data = in_file.read()
    compressed_data = zlib.compress(data, 9)  
    out_file.write(compressed_data)
    
    in_file.close()
    out_file.close()
    
    bd_logger("Ending zlib...")    
    


def main():
    
    in1 = "C:\\Users\\Arek\\Desktop\\Silent_Hill_SM_Tools_v7\\TextConv\\OUT\\2C238264_fixed_out.ini"
    out2 = "C:\\Users\\Arek\\Desktop\\Silent_Hill_SM_Tools_v7\\TextConv\\OUT\\2C238264_fixed_out2.ini"
    out3 = "C:\\Users\\Arek\\Desktop\\Silent_Hill_SM_Tools_v7\\TextConv\\OUT\\2C238264_fixed_out3.ini"
    
    eng1 = "C:\\Users\\Arek\\Desktop\\Silent_Hill_SM_Tools_v7\\TextConv\\OUT\\2C238264_eng.ini"
    eng2 = "C:\\Users\\Arek\\Desktop\\Silent_Hill_SM_Tools_v7\\TextConv\\OUT\\2C238264_eng_short.ini"    
  
    #debug_INI_file(in1, out2)
    #INI_padding(out2, out3)
    
    
    #p_in_filepath = "C:\\Users\\Arek\\Desktop\\Silent_Hill_SM\\USA_ROM\\data_arc_test\\DATA_1316"
    #p_out_filepath = "C:\\Users\\Arek\\Desktop\\Silent_Hill_SM\\USA_ROM\\data_arc_test\\DATA_1316_temp"
    #unzlib_file(p_in_filepath, p_out_filepath)
    
    p_in_filepath = "C:\\Users\\Arek\\Desktop\\Silent_Hill_SM_Tools_v7\\TextConv\\IN\\2C238264"
    p_out_filepath = "C:\\Users\\Arek\\Desktop\\Silent_Hill_SM\\USA_ROM\\data_arc_test\\DATA_1316_222"
    zlib_file(p_in_filepath, p_out_filepath)
        
    bd_logger("End of main...")
    
    
    
main()