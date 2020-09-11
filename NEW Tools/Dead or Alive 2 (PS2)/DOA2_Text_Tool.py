# -*- coding: utf-8 -*-

# Tested on Python 3.8.0
# This tool should be used with Dead or Alive 2  (PS2 USA version - SLUS_200.71)

# Ver    Date        Author
# v0.1   11.09.2020  Bartlomiej Duda

import os
import sys
import struct



def bd_logger(in_str):
    import datetime
    now = datetime.datetime.now()
    print(now.strftime("%d-%m-%Y %H:%M:%S") + " " + in_str)    
    

def read_str(in_file):
    main_encoding = "windows-1252"
    out_str = bytes() 
    out_str_d = ""
    while 1:
        ch = struct.unpack('c', in_file.read(1))[0]
        ch_d = ch.decode(main_encoding)
        #print("ch: " + str(ch))
        if ord(ch_d) != 0:
            out_str += ch
        else:
            out_str_d = out_str.decode(main_encoding)
            return out_str_d
    return out_str_d

def read_nulls(in_file):
    while 1:
        back_offset = in_file.tell()
        ch = struct.unpack('c', in_file.read(1))[0].decode("windows-1252")
        if ord(ch) != 0:
            in_file.seek(back_offset)
            return


def collect_data(in_file_path, out_file_path, out2_file_path):
    '''
    Function for collecting text data
    '''    
    bd_logger("Starting collect_data...")    
    
    in_file = open(in_file_path, 'rb')
    out_file = open(out_file_path, 'wt+', encoding="windows-1252")
    out2_file = open(out2_file_path, 'wt+', encoding="windows-1252")
    
    
    #out1
    in_file.seek(4276792) #go to text1 start address
    offset_arr = []
    j = 0
    p_flag = 0
    for i in range(2105):
        j += 1
        curr_offset = in_file.tell()
        offset_arr.append(curr_offset)
        strr = read_str(in_file)
        read_nulls(in_file)
        out_str = str(i+1) + ") " + "str_offset: " + str(curr_offset) + " my_str: " + strr
        #print(out_str)
        out_file.write(out_str + "\n")
        
        
    #out2
    in_file.seek(4519496) #go to text2 start address
    offset_arr = []
    j = 0
    p_flag = 0
    i = 0
    for i in range(245):
        j += 1
        curr_offset = in_file.tell()
        offset_arr.append(curr_offset)
        strr = read_str(in_file)
        read_nulls(in_file)
        out_str = str(i+1) + ") " + "str_offset: " + str(curr_offset) + " my_str: " + strr
        print(out_str)
        out2_file.write(out_str + "\n")    
            
   
    
    in_file.close()
    out_file.close()
    out2_file.close()
    bd_logger("Ending collect_data...")    



    
def extract_text():
    pass #TODO
    
    
def main():
    
    main_switch = 1
    # 1 - text data collect

    

    if main_switch == 1:
        p_in_filepath = "C:\\Users\\Arek\\Desktop\\DOA2 PS2\\GAME_FILES\\SLUS_200.71"
        p_out_filepath = "C:\\Users\\Arek\\Desktop\\DOA2 PS2\\GAME_FILES\\out.txt"
        p_out2_filepath = "C:\\Users\\Arek\\Desktop\\DOA2 PS2\\GAME_FILES\\out2.txt"
        collect_data(p_in_filepath, p_out_filepath, p_out2_filepath)
        
   
    else:
        print("Wrong option selected!")
        
        
    
    bd_logger("End of main...")    
    
    
    
main()