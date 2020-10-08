# -*- coding: utf-8 -*-

# Tested on Python 3.8.0
# This tool should be used with Treasure Cove 2.0

# Ver    Date        Author
# v0.1   08.10.2020  Bartlomiej Duda


import os
import sys
import struct



def bd_logger(in_str):
    import datetime
    now = datetime.datetime.now()
    print(now.strftime("%d-%m-%Y %H:%M:%S") + " " + in_str)    
    


def export_tld(in_file_path, out_folder_path):
    '''
    Function for exporting data from TLD files
    '''    
    bd_logger("Starting export_tld...")    
    
    tld_file = open(in_file_path, 'rb')
    
    
    tld_file.read(8)
    num_of_entries = struct.unpack("<L", tld_file.read(4))[0]
    
    print("num_of_entries: " + str(num_of_entries))
    
    
    for i in range(num_of_entries):
        #reading entries
        ID = struct.unpack("<L", tld_file.read(4))[0]
        nulls = tld_file.read(4)
        res_type = tld_file.read(4).decode("UTF8")
        file_offset = struct.unpack("<L", tld_file.read(4))[0]
        file_size = struct.unpack("<L", tld_file.read(4))[0]
        #print(str(i+1) + ") " + "\tID: " + str(ID) + "\t res_type: " + res_type + "\t file_offset: " + str(file_offset) + "\t file_size: " + str(file_size) )
        
        file_ext = ""
        
        if res_type == "SSND":
            file_ext = ".ssnd"
        elif res_type == "AO  ":
            file_ext = ".ao"
        elif res_type == "BNDL":
            file_ext = ".bndl"
        elif res_type == "RRGB":
            file_ext = ".rrgb"
        elif res_type == "OTHR":
            file_ext = ".othr"        
        elif res_type == "LIPS":
            file_ext = ".lips" 
        elif res_type == "FFNT":
            file_ext = ".ffnt"         
            
        else:
            bd_logger("Unknown res type: " + res_type)
            file_ext = ".bin"
        
        back_offset = tld_file.tell()
        
        #read file data
        tld_file.seek(file_offset)
        file_data = tld_file.read(file_size)
        
        #save file data 
        out_file_path = out_folder_path + "file" + str(i+1) + file_ext 
        out_file = open(out_file_path, 'wb+')
        out_file.write(file_data)
        out_file.close()
        
        
        tld_file.seek(back_offset)
        
    

   
    
    tld_file.close()
    bd_logger("Ending export_tld...")    
    
    
    
    
def main():
    
    main_switch = 1
    # 1 - tld export 

    if main_switch == 1:
        #p_in_file_path = "C:\\Users\\Arek\\Desktop\\TC4SOUND.TLD"
        #p_out_folder_path = "C:\\Users\\Arek\\Desktop\\SOUND_OUT\\"
        
        #p_in_file_path = "C:\\Users\\Arek\\Desktop\\TCV256H.TLD"
        #p_out_folder_path = "C:\\Users\\Arek\\Desktop\\TCV256\\"  
        
        p_in_file_path = "C:\\Users\\Arek\\Desktop\\TCV.TLD"
        p_out_folder_path = "C:\\Users\\Arek\\Desktop\\TCV\\"         
        
        export_tld(p_in_file_path, p_out_folder_path)
            
    else:
        print("Wrong option selected!")
        
    bd_logger("End of main...")    
    
    
    
main()