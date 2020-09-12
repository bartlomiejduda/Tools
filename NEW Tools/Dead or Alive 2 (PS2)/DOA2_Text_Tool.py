# -*- coding: utf-8 -*-

# Tested on Python 3.8.0
# This tool should be used with Dead or Alive 2  (PS2 USA version - SLUS_200.71)

# Ver    Date        Author
# v0.1   11.09.2020  Bartlomiej Duda
# v0.2   12.09.2020  Bartlomiej Duda

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



    
def extract_text(in_exe_filepath, out_text_filepath):
    '''
    Function for extracting english texts
    '''    
    bd_logger("Starting extract_text...")    
    
    in_file = open(in_exe_filepath, 'rb')
    out_file = open(out_text_filepath, 'wt+', encoding="windows-1252")
    eng_data_file = open("strings_eng_data.txt", 'rt')
    
    
    offset_arr = []
    size_arr = []
    texts_count = 0
    for line in eng_data_file: #gathering data for text extraction
        texts_count += 1
        line = line.rstrip("\n")
        
        off_str = line.split("\t")[0]
        size_str = line.split("\t")[1]
        
        off_i = int(off_str, 16)
        size_i = int(size_str, 16)
        
        offset_arr.append(off_i)
        size_arr.append(size_i)
        
    
    
    for i in range(texts_count): #saving texts to file
        in_file.seek(offset_arr[i])
        text_str = in_file.read(size_arr[i]).decode("windows-1252")
        #print(text_str)
        out_str = str(offset_arr[i]) + "_" + str(size_arr[i]) + "=" + text_str
        out_file.write(out_str + "\n")
    
    
    
    
    eng_data_file.close()
    in_file.close()
    out_file.close()
    bd_logger("Ending extract_text...")        
    
    
    
    
def main():
    
    main_switch = 2
    # 1 - text data collect
    # 2 - text extract

    

    if main_switch == 1:
        p_in_filepath = "C:\\Users\\Arek\\Desktop\\DOA2 PS2\\GAME_FILES\\SLUS_200.71"
        p_out_filepath = "C:\\Users\\Arek\\Desktop\\DOA2 PS2\\GAME_FILES\\out.txt"
        p_out2_filepath = "C:\\Users\\Arek\\Desktop\\DOA2 PS2\\GAME_FILES\\out2.txt"
        collect_data(p_in_filepath, p_out_filepath, p_out2_filepath)
        
    elif main_switch == 2:
        p_in_filepath = "C:\\Users\\Arek\\Desktop\\DOA2 PS2\\GAME_FILES\\SLUS_200.71"
        p_out_filepath = "C:\\Users\\Arek\\Desktop\\DOA2 PS2\\GAME_FILES\\Dead_or_alive_2_ENG_script.ini"
        extract_text(p_in_filepath, p_out_filepath)
   
    else:
        print("Wrong option selected!")
        
        
    
    bd_logger("End of main...")    
    
    
    
main()