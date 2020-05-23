# -*- coding: utf-8 -*-

# Tested on Python 3.8.0
# This tool should be used with Harry Potter and the Chamber of Secrets (PS2)

# Ver    Date        Author
# v0.1   23.05.2020  Bartlomiej Duda

import os
import sys
import struct



def bd_logger(in_str):
    import datetime
    now = datetime.datetime.now()
    print(now.strftime("%d-%m-%Y %H:%M:%S") + " " + in_str)    
    


def export_text(in_TEXT_filepath, out_INI_filepath):
    '''
    Function for exporting text from strings.loc file
    '''    
    bd_logger("Starting export_text...")    
    
    text_file = open(in_TEXT_filepath, 'rb')
    ini_file = open(out_INI_filepath, 'wt+')
    
    #LOCH header read
    header_data = text_file.read(20) #TODO 
    
    #LOCL read
    magic = text_file.read(4)
    LOCL_block_size = text_file.read(8)
    num_of_LOCL_entries = struct.unpack('<I', text_file.read(4))[0] - 1
    data_start = text_file.read(4)
    
    off_array = []
    for i in range(num_of_LOCL_entries):
        text_offset = struct.unpack('<I', text_file.read(4))[0] + 20  #TODO 
        off_array.append(text_offset)
        
    end_offset = os.stat(in_TEXT_filepath).st_size
    off_array.append(end_offset)
        
    for i in range(num_of_LOCL_entries):
        str_length = off_array[i+1] - off_array[i]
        text_file.seek(off_array[i])
        str_out = "BD_TRANSLATE_TEXT=" + str(text_file.read(str_length).decode("utf8", errors="ignore")).replace("\n", "\\n") + "\n"
        ini_file.write(str_out)
        
    
    
 
    text_file.close()
    ini_file.close()
    bd_logger("Ending export_text...")    
    
    
    
    
def main():
    
    main_switch = 1
    # 1 - text export 


    if main_switch == 1:
        p_in_TEXT_filepath = "C:\\Users\\Arek\\Desktop\\strings.loc"
        p_out_INI_filepath = "C:\\Users\\Arek\\Desktop\\strings.loc.ini"
        export_text(p_in_TEXT_filepath, p_out_INI_filepath)
            
    else:
        print("Wrong option selected!")
        
        
    
    bd_logger("End of main...")    
    
    
    
main()