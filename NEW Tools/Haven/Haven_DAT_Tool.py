# -*- coding: utf-8 -*-

'''
Copyright © 2021  Bartłomiej Duda
License: GPL-3.0 License 
'''


# Program tested on Python 3.7.0
# It should be used with Haven

# Ver    Date        Author               Comment
# v0.1   13.02.2021  Bartlomiej Duda      -

import os
import sys
import struct
import datetime


def bd_logger(in_str):
    '''
    Function for logging debug messages
    '''   
    now = datetime.datetime.now()
    print(now.strftime("%d-%m-%Y %H:%M:%S") + " " + in_str)    
    

def calculate_padding_len(in_len):
    padding_val = (8 - (in_len % 8)) % 8
    return padding_val

#def calculate_padding_len_v2(in_len):
    #mod_res = int(in_len % 4)
    #if mod_res == 0:
        #return mod_res
    #else:
        #res = 4 - mod_res
        #return res  
 
def calculate_padding_len_v3(in_len):
    div = 4
    padding_val = (div - (in_len % div)) % div
    return padding_val   
    

def read_nulls(in_file):
    while 1:
        back_offset = in_file.tell()
        ch = struct.unpack('c', in_file.read(1))[0].decode("windows-1252")
        if ord(ch) != 0:
            in_file.seek(back_offset)
            return


def export_data(in_file_path, out_folder_path):
    '''
    Function for exporting data from DAT files
    '''    
    bd_logger("Starting export_data...")  
    
    if not os.path.exists(out_folder_path):
        os.makedirs(out_folder_path)      
    
    dat_file = open(in_file_path, 'rb')
    out_file = open(out_folder_path + "out.txt", "wb+")
    
    
    for i in range(99999999):
        
        
        person_offset = dat_file.tell()
        
        
        
        person_string = struct.unpack("4s", dat_file.read(4))[0].decode("utf8").rstrip('\x00')
        if person_string == "":
            person_string = "None"
            
            
        elif person_string in ('\x05'): # workaround!
            dat_file.seek( dat_file.tell() - 4)
            person_string_len = struct.unpack("<L", dat_file.read(4))[0]
            person_string = dat_file.read(person_string_len).decode("utf8")
            padding_len = calculate_padding_len(person_string_len)
            dat_file.read(padding_len)             
            
            
        elif person_string in ('\x02'): # workaround!
            dat_file.read(4)
            person_string = "Yu"
        elif person_string in ('\x03'): # workaround!
            dat_file.read(4)
            person_string = "Kay"
        elif person_string in ("Eren", "Horn", "Ozia"): # workaround!
            dat_file.seek(person_offset)
            person_string = struct.unpack("8s", dat_file.read(8))[0].decode("utf8").rstrip('\x00')
            
        print("PERSON: " + str(person_string))
        
        
        
        curr_offset = dat_file.tell()
        entry_ID_len = struct.unpack("<L", dat_file.read(4))[0]
        entry_ID = dat_file.read(entry_ID_len).decode("utf8")
        print("entry_ID_off: " + str(curr_offset) + 
            " entry_ID: " + str(entry_ID))
        
        padding_len = calculate_padding_len_v3(entry_ID_len) #1
        dat_file.read(padding_len)
        
        default_str_len = struct.unpack("<L", dat_file.read(4))[0]
        default_str = dat_file.read(default_str_len)
        
        padding_len = calculate_padding_len_v3(default_str_len)
        dat_file.read(padding_len)   
        
        num_of_languages = struct.unpack("<L", dat_file.read(4))[0]
        
        #if num_of_languages == 0:
            #dat_file.read(4)
            #continue

        
        
        for j in range(num_of_languages):

            lang_ID_length = struct.unpack("<L", dat_file.read(4))[0]
            lang_ID = dat_file.read(lang_ID_length)  
            
            padding_len = calculate_padding_len_v3(lang_ID_length)
            dat_file.read(padding_len)      
            
            string_length = struct.unpack("<L", dat_file.read(4))[0]
            str_offset = dat_file.tell()
            
            if str_offset > 4375884 - 1:
                a = 5 # debug
            
            
            if string_length == 0:
                out_string = ""
            else:
                out_string = dat_file.read(string_length).decode("utf8")
            
            padding_len = calculate_padding_len_v3(string_length) # 2
            dat_file.read(padding_len)  

            
            end_offset = dat_file.tell()
            
            print(str(lang_ID.decode("utf8")) + "= " + 
                  " str_offset: " + str(str_offset) + 
                  " str_len: " + str(string_length) +
                  " " + str(out_string))
                

            
            
            
        num_of_something = struct.unpack("<L", dat_file.read(4))[0]
        
        for i in range(num_of_something):
            some_value = dat_file.read(4)
    
   
    
    
    
    
    
    dat_file.close()
    bd_logger("Ending export_data...")    
    
    
    
    
def main():
    '''
    Main function of this program. If you are planning to use it,
    you should adjust paths first.
    '''   
    main_switch = 1
    # 1 - data export 
    

    if main_switch == 1:
        p_in_file_path = "C:\\Users\\Arek\\Desktop\\LocalizationData.dat"
        p_out_folder_path = "C:\\Users\\Arek\\Desktop\\LocalizationData.dat_OUT\\"
        export_data(p_in_file_path, p_out_folder_path)
        
    else:
        bd_logger("Wrong option selected!")
        
        
    
    bd_logger("End of main...")    
    
    
    
main()