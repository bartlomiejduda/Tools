# -*- coding: utf-8 -*-

# Tested on Python 3.8.0
# This tool should be used with Tekken Mobile Java game

# Ver    Date        Name
# v0.1   05.02.2020  Bartlomiej Duda
# v0.2   08.02.2020  Bartlomiej Duda
# v0.3   09.02.2020  Bartlomiej Duda
# v0.4   10.02.2020  Bartlomiej Duda



VERSION_NUM = "v0.4"


import os
import sys
import struct



def bd_logger(in_str):
    import datetime
    now = datetime.datetime.now()
    print(now.strftime("%d-%m-%Y %H:%M:%S") + " " + in_str)    


def read_loc(p_input_loc_filepath, p_out_filepath):
    bd_logger("Starting Tekken Mobile loc read...")
    loc_file = open(p_input_loc_filepath, 'rb') 
    out_file = open(p_out_filepath, 'wt+') 
    str_arr = []
    size_of_the_header = struct.unpack('>i', loc_file.read(4))[0]
    num_of_text_strings = struct.unpack('>i', loc_file.read(4))[0]
    
    loc_file.seek(loc_file.tell() + size_of_the_header) #skip header
    
    for i in range(num_of_text_strings):
        str_length = struct.unpack('>H', loc_file.read(2))[0]
        str_read = loc_file.read(str_length).decode("utf-8") 
        #print("Str: " + str(str_read))
        str_arr.append(str_read)
        
    for i in range(num_of_text_strings):
        out_file.write("BD_TRANSLATE_TEXT_TAG=")
        out_file.write( str_arr[i].replace("\n", "\\n")
                                  .replace("™", "<TM_SIGN>")
                                  .replace("©", "<CP_SIGN>")
                       
                       )
        out_file.write("\n")

    #print("Offset: " + str(loc_file.tell()))
    
    bd_logger("Ending Tekken Mobile loc read...")
    


def write_loc(p_input_ini_filepath, p_loc_out_filepath):
    bd_logger("Starting Tekken Mobile loc write...")
    loc_file = open(p_loc_out_filepath, 'rb') 
    ini_file = open(p_input_ini_filepath, 'rt', encoding="utf-8")  #  windows-1250 or utf-8
    
    size_of_the_header = struct.unpack('>i', loc_file.read(4))[0]
    num_of_text_strings = struct.unpack('>i', loc_file.read(4))[0]
    header_data = loc_file.read(size_of_the_header)
    loc_file.close()
    
    cnt = 0
    line_arr = []
    for line in ini_file:
        cnt += 1
        line = line.split("BD_TRANSLATE_TEXT_TAG=")[1]
        line_arr.append(line)
        #print(str(cnt) + ") " + line)
    ini_file.close()
    
    loc_file = open(p_loc_out_filepath + "_NEW", 'wb+') 
    loc_file.write(struct.Struct(">i").pack(size_of_the_header))
    loc_file.write(struct.Struct(">i").pack(num_of_text_strings))
    loc_file.write(header_data)
    
    for line_a in line_arr:
        
        line_res = ( line_a.rstrip("\n").replace("Ż", "À")
                                        .replace("Ó", "Ó")
                                        .replace("Ł", "Ò")
                                        .replace("Ć", "Ö")
                                        .replace("Ę", "É")
                                        .replace("Ś", "Á")
                                        .replace("Ą", "Â")
                                        .replace("Ź", "Ä")
                                        .replace("Ń", "Ñ")
                     
                                        .replace("ż", "à")
                                        .replace("ó", "ó")
                                        .replace("ł", "ò")
                                        .replace("ć", "ö")
                                        .replace("ę", "é")
                                        .replace("ś", "á")
                                        .replace("ą", "â")
                                        .replace("ź", "ä")
                                        .replace("ń", "ñ")
                     
                                        .encode("utf-8").replace(b"\\n", b"\n")   #  windows-1250 or utf-8
                                        .replace(b"<TM_SIGN>", b"\xE2\x84\xA2")
                                        .replace(b"<CP_SIGN>", b"\xC2\xA9")
                                        
         
                     )
        
        line_res_len = len(line_res)
        loc_file.write(struct.Struct(">H").pack(line_res_len))
        loc_file.write(line_res )   
    
    bd_logger("Ending Tekken Mobile loc write...")
    



bd_logger("Tekken Mobile Java Tool " + VERSION_NUM)
    
#  LOC to INI    
#input_loc_filepath = "C:\\Users\\Arek\\Desktop\\TRAD_english.loc"
#out_filepath = "C:\\Users\\Arek\\Desktop\\OUT.ini"
#read_loc(input_loc_filepath, out_filepath)


#  INI to LOC
input_ini_filepath = "C:\\Users\\Arek\\Desktop\\OUT.ini"
loc_out_filepath = "C:\\Users\\Arek\\Desktop\\TRAD_english.loc"
write_loc(input_ini_filepath, loc_out_filepath)