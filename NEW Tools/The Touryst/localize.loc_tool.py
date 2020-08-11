# -*- coding: utf-8 -*-

# Tested on Python 3.8.0
# This tool should be used with The Touryst

# Ver    Date        Author
# v0.1   11.08.2020  Bartlomiej Duda
# v0.2   11.08.2020  Bartlomiej Duda


import os
import sys
import struct



def bd_logger(in_str):
    import datetime
    now = datetime.datetime.now()
    print(now.strftime("%d-%m-%Y %H:%M:%S") + " " + in_str)    
    


def get_loc_table(in_arr, in_file):
    '''
    Function for getting LOC table
    '''      
    #bd_logger("Starting get_loc_table...")  
    
    
    in_file.seek(108)
    c_str = ""
    #str_arr = []
    j = 0
    
    for i in range(5175):
    
        c_char = struct.unpack("c", in_file.read(1))[0].decode("utf8")
        
        
        if ord(c_char) == 0:
            j += 1
            #print("i=" + str(i) + ", j=" + str(j) + " " + c_str)
            in_arr.append(c_str)
            c_str = ""
        else:
            c_str += c_char
            
        in_file.read(7)
    
    
    
    #bd_logger("Ending get_loc_table...")  

def readcstr(f):
    r_str = ""
    
    while 1:
        back_offset = f.tell()
        try:
            r_char = struct.unpack("c", f.read(1))[0].decode("utf8")
        except:
            f.seek(back_offset)
            temp_char = struct.unpack("<H", f.read(2))[0]
            r_char = chr(temp_char)
        if ord(r_char) == 0:
            return r_str
        else:
            r_str += r_char    


def export_text(in_file_path, out_folder_path):
    '''
    Function for exporting texts from LOC files
    '''    
    bd_logger("Starting export_text...")    
    
    in_file = open(in_file_path, 'rb')
    
    #get loc table
    loc_table = []
    get_loc_table(loc_table, in_file)
    
    
    #save loc table
    loc_out = open(out_folder_path + "\\loc_table_out.txt", "wt+")
    for loc_name in loc_table:
        loc_out.write(loc_name + "\n")
    loc_out.close()
    
    
    #read offsets table
    start_off = 41477
    in_file.seek(start_off)
    num_of_strings = struct.unpack("<L", in_file.read(4))[0] + 1
    in_file.read(3)
    
    num_of_languages = 4
    

    for i in range(num_of_languages):

        lang_code = readcstr(in_file)
        lang_name = readcstr(in_file)
        curr_off = in_file.tell()
        
        if lang_code in ("sp"):
            pass
        elif lang_code in ("ge"):
            in_file.seek(curr_off + 3)
        else:
            in_file.seek(curr_off + 1)
        
        out_file_path = out_folder_path + "\\" + lang_code + "_" + lang_name + ".txt"
        out_file = open(out_file_path, "wt+", encoding="utf8")
        
        
        offset_arr = []
        
        for i in range(num_of_strings):
            tempppp = in_file.tell()
            offset = struct.unpack("<L", in_file.read(4))[0]
            #print(str(i+1) + ") " + str(offset))
            offset_arr.append(offset)
        
        base_addr = in_file.tell()
        
        for i in range(num_of_strings):
            real_offset = base_addr + offset_arr[i]
            #print(real_offset)
            in_file.seek(real_offset)
            str1 = readcstr(in_file)
            #print(str1)
            out_file.write(str1 + "\n")
            
        out_file.close()
   
   
    
    in_file.close()
    bd_logger("Ending export_text...")    
    
    
    
    
def main():
    
    main_switch = 1
    # 1 - loc export 
  
    if main_switch == 1:
        p_in_file_path = "C:\\Users\\Arek\\Desktop\\localize.loc"
        p_out_folder_path = "C:\\Users\\Arek\\Desktop\\localize.loc_OUT"
        export_text(p_in_file_path, p_out_folder_path)

            
    else:
        print("Wrong option selected!")
        
        
    
    bd_logger("End of main...")    
    
    
    
main()