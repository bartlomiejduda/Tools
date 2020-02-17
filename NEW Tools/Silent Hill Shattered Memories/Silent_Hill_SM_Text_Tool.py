# -*- coding: utf-8 -*-

# Tested on Python 3.8.0
# This tool should be used with Silent Hill: Shattered Memories (PSP)

# Ver    Date        Author
# v0.1   16.02.2020  Bartlomiej Duda
# v0.2   16.02.2020  Bartlomiej Duda
# v0.3   17.02.2020  Bartlomiej Duda
# v0.4   17.02.2020  Bartlomiej Duda
# v0.5   17.02.2020  Bartlomiej Duda

VERSION_NUM = "v0.5"

import os
import sys
import struct

def bd_logger(in_str):
    import datetime
    now = datetime.datetime.now()
    print(now.strftime("%d-%m-%Y %H:%M:%S") + " " + in_str)    
    
def decode_char(in_num):
    if int(in_num) < 5:        
        return "<TAG_" + str(in_num) + ">"
    else:
        #return "<UNKNOWN_TAG_" + str(in_num) + ">"
        return str(chr(in_num))
    

def read_SUB(in_sub_filepath):
    bd_logger("Starting read_SUB function...")
    sub_file = open(in_sub_filepath, 'rb') 
    
    ver_num = struct.unpack('<I', sub_file.read(4))[0]
    if ver_num != 2:
        bd_logger("Wrong version number!")
        return
    
    num_of_strings = struct.unpack('<I', sub_file.read(4))[0]
    hash_arr = []
    str_offset_arr = []
    tell_arr = []
    text_arr = []
    
    for i in range(num_of_strings):
        hash_i = struct.unpack('<I', sub_file.read(4))[0]
        offset_i = struct.unpack('<I', sub_file.read(4))[0] * 2
        tell_i = sub_file.tell()
        hash_arr.append(hash_i)
        str_offset_arr.append(offset_i)
        tell_arr.append(tell_i)
    
    
    base_offset = sub_file.tell()
    for i in range(num_of_strings):
        try:
            str1 = ""
            sub_file.seek(base_offset + str_offset_arr[i])
            offset_start = sub_file.tell()
            while(1):
                ch = struct.unpack('<H', sub_file.read(2))[0]
                if ch == 0:
                    break
                else:
                    str1 += decode_char(ch)
            #print( str(i+1) + ") " + str1 )  
            str1 = ( str1.replace("\n", "\\n")
                         .replace("\r", "\\r")  
                         .replace("™", "<TM_SIGN>")
                     )
            text_arr.append(str1)
        except:
            offset_end = sub_file.tell()
            print("End of file! Offset: " + str(offset_end) )
                
        
    print("off_end: " + str( sub_file.tell() ) )
    sub_file.close()
    
    
    ini_file = open(in_sub_filepath + ".ini", 'wb+') 
    for i in range(num_of_strings):
        #print(text_arr[i])
        ini_file.write(b"BD_TRANSLATE_TEXT=")
        ini_file.write(text_arr[i].encode("utf-8", errors="xmlcharrefreplace") )
        #ini_file.write(text_arr[i].encode("utf-8", errors="namereplace") )
        #ini_file.write(text_arr[i].encode("utf-8", errors="backslashreplace") )
        
        ini_file.write(b"\n")
    
    ini_file.close()
    
    bd_logger("Ending read_SUB function...")


def read_SUB_ALL():
    file_arr_all = ["DATA_47", "DATA_48", "DATA_49", "DATA_50", "DATA_51", "DATA_52", "DATA_1317",
                "DATA_1318", "DATA_1319", "DATA_1320", "DATA_1321", "DATA_1322", "DATA_1323",
                "DATA_1324", "DATA_1325" ]
    
    file_arr_eng = ["DATA_47", "DATA_1317", "DATA_1318"]
    
    # read SUB loop
    for file_i in file_arr_eng:
        p_in_sub_filepath = "C:\\Users\\Arek\\Desktop\\SUB_ENG\\" + file_i + ".sub"
        read_SUB(p_in_sub_filepath)
    print("FINISHED ALL!")


def generate_hash(in_str):
    return 858993459 #TODO

def convert_str(in_str):
    out_str = b""
    for ch in in_str:
        if ch < 5:
            out_str += struct.Struct("<B").pack(ch)
        else:
            out_str += struct.Struct("<H").pack(ch)
    return out_str

def write_SUB(in_ini_filepath):
    bd_logger("Starting write_SUB function...")
    ini_file = open(in_ini_filepath, 'rt')
    
    ini_line_arr = []
    num_of_lines = 0
    for line in ini_file:
        
        line_i = line.split("BD_TRANSLATE_TEXT=")[1].rstrip("\n")
        line_i = (  line_i
                    
                    .replace("\\n", "\n")
                    .replace("\\r", "\r")
                    
                    .encode("utf-8") )        
        
        
        line_i = convert_str(line_i)
        line_i = (  line_i
                    
                    .replace( convert_str(b"<TAG_1>"), b"\x01\x00")
                    #.replace(b"<\x00T\x00A\x00G\x00_\x002\x00>", b"\x02\x00")
                    .replace( convert_str(b"<TM_SIGN>"), b"\x22\x21")
                    
                    
                    #.replace( ("<TM_SIGN>".encode("utf-16")), b"\x05\x00")
                    #.replace( ("<TAG_1><TAG_1>".encode("utf-16")), b"\x01\x00\x01\x00")
                    #.replace(b"\x3C\x00\x54\x00\x41\x00\x47\x00\x5F\x00\x31\x00\x3E", b"\x01\x00") #<TAG_1>
                    .replace("<TAG_2>".encode("utf-16"), b"\x02\x00")
                    .replace("<TAG_3>".encode("utf-16"), b"\x03\x00")
                    .replace("<TAG_4>".encode("utf-16"), b"\x04\x00")
                    .replace("<TAG_5>".encode("utf-16"), b"\x05\x00")
                    #.replace(b"\x3C\x00\x54\x00\x4D\x00\x5F\x00\x53\x00\x49\x00\x47\x00\x4E\x00\x3E", b"\x22\x21\x20")  #<TM_SIGN>
                    

                    )
        
        line_i = line_i + b"\x00\x00" #padding
        
        ini_line_arr.append(line_i)
        num_of_lines += 1
        
    ini_file.close()
    
    #for line in ini_line_arr:
        #print(line)
    
    sub_filepath = in_ini_filepath.rstrip(".ini") + "_NEW" 
    print(sub_filepath)
    sub_file = open(sub_filepath, 'wb+')
    sub_file.write(struct.Struct("<I").pack(2)) #version num
    sub_file.write(struct.Struct("<I").pack(num_of_lines)) #number of strings
    
    hash_arr = []
    for i in range(num_of_lines): #generate hashes
        str_h = "hhh" #TODO 
        hash_arr.append(  generate_hash(str_h) )
    
    offset_arr = []    
    base_offset = 8 + (4 * num_of_lines) + (4 * num_of_lines)
    curr_offset = 0
    for i in range(num_of_lines): #generate offsets 
        offset_i = int(curr_offset / 2)
        #print("offset_i: " + str(offset_i) + ", curr_offset: " + str(curr_offset) + ", len_line_arr: " + str(len(ini_line_arr[i])) )
        curr_offset += len(ini_line_arr[i])
        offset_arr.append(offset_i)
        
    for i in range(num_of_lines): #writing hash/offset array 
        sub_file.write(struct.Struct("<I").pack(hash_arr[i]))
        sub_file.write(struct.Struct("<I").pack(offset_arr[i]))
        
    for i in range(num_of_lines): #writing strings 
        sub_file.write(ini_line_arr[i] )
    
    
    
    
    sub_file.close()
    
    bd_logger("Ending write_SUB function...")


    

#  read SUB 
#p_in_sub_filepath = "C:\\Users\\Arek\\Desktop\\Silent_Hill_SM\\out_s2\\DATA_47.sub"
#p_in_sub_filepath = "C:\\Users\\Arek\\Desktop\\SUBs\\DATA_1323.sub"
#read_SUB(p_in_sub_filepath)

#read_SUB_ALL()



#write SUB
p_in_ini_filepath = "C:\\Users\\Arek\\Desktop\\SUB_ENG\\DATA_47.sub.ini"
write_SUB(p_in_ini_filepath)