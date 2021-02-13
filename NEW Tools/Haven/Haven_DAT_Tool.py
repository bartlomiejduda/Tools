# -*- coding: utf-8 -*-

'''
Copyright © 2021  Bartłomiej Duda
License: GPL-3.0 License 
'''


# Program tested on Python 3.7.0
# It should be used with Haven

# Ver    Date        Author               Comment
# v0.1   14.01.2021  Bartlomiej Duda      -

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

def calculate_padding_len_v2(in_len):
    mod_res = int(in_len % 4)
    if mod_res == 0:
        return mod_res
    else:
        res = 4 - mod_res
        return res  
 
def calculate_padding_len_v3(in_len):
    padding_val = (4 - (in_len % 4)) % 4
    return padding_val   
    

def read_nulls(in_file):
    while 1:
        back_offset = in_file.tell()
        ch = struct.unpack('c', in_file.read(1))[0].decode("windows-1252")
        if ord(ch) != 0:
            in_file.seek(back_offset)
            return


#def read_person_string(in_file):
    #back_offset = in_file.tell()
    #try: # this is only a workaround!
        #p_string_ID = struct.unpack("<L", in_file.read(4))[0]
        #if p_string_ID == 1:
            #person_str_len = struct.unpack("<L", in_file.read(4))[0]
            #person_str = in_file.read(person_str_len)
        #elif p_string_ID == 3:
            #person_str_len = p_string_ID
            #person_str = in_file.read(person_str_len)
        #else:
            #raise
        
        #print("person_str: " + str(person_str))
        
    #except:
        #in_file.seek(back_offset)
        #return


def export_data(in_file_path, out_folder_path):
    '''
    Function for exporting data from DAT files
    '''    
    bd_logger("Starting export_data...")  
    
    if not os.path.exists(out_folder_path):
        os.makedirs(out_folder_path)      
    
    dat_file = open(in_file_path, 'rb')
    
    #num_of_entries = struct.unpack("<L", dat_file.read(4))[0]
    #print(num_of_entries)
    
    for i in range(99999999):
        
        #read_person_string(dat_file)
        #read_nulls(dat_file)
        
        person_offset = dat_file.tell()
        person_string = struct.unpack("4s", dat_file.read(4))[0].decode("utf8").rstrip('\x00')
        if person_string == "":
            person_string = "None"
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
        
        padding_len = calculate_padding_len(default_str_len)
        dat_file.read(padding_len)   
        #read_nulls(dat_file)
        #dat_file.read(8)
        
        num_of_languages = struct.unpack("<L", dat_file.read(4))[0]
        
        if num_of_languages == 0:
            #read_nulls(dat_file)
            dat_file.read(4)
            continue
            #num_of_subentries = struct.unpack("<L", dat_file.read(4))[0]
            
            #for k in range(num_of_subentries):
                #len_of_str = struct.unpack("<L", dat_file.read(4))[0]
                #Yu_str = dat_file.read(len_of_str)
                #padding_len = calculate_padding_len(len_of_str)
                #dat_file.read(padding_len)    
                
            ##dat_file.read(4)
            #read_nulls(dat_file)
        
        #else:
        
        
        for j in range(num_of_languages):

            lang_ID_length = struct.unpack("<L", dat_file.read(4))[0]
            lang_ID = dat_file.read(lang_ID_length)  
            #print(lang_ID) = struct.unpack <
            
            padding_len = calculate_padding_len_v3(lang_ID_length)
            dat_file.read(padding_len)      
            
            string_length = struct.unpack("<L", dat_file.read(4))[0]
            str_offset = dat_file.tell()
            
            if str_offset > 167915:
                a = 5 # debug
            
            
            if string_length == 0:
                back_offset = dat_file.tell()
                temp = struct.unpack("<L", dat_file.read(4))[0]
                if temp > 0:
                    dat_file.seek(back_offset)
                #read_nulls(dat_file)
                out_string = ""
            else:
                out_string = dat_file.read(string_length).decode("utf8")
            
            padding_len = calculate_padding_len_v3(string_length) # 2
            dat_file.read(padding_len)  
            #read_nulls(dat_file)
            #dat_file.seek(dat_file.tell() - 4)
            
            end_offset = dat_file.tell()
            
            print("str_offset: " + str(str_offset) + 
                  " str_len: " + str(string_length) +
                  " " + str(out_string))
                
            #dat_file.read(4)
    
   
    
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