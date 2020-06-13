# -*- coding: utf-8 -*-

# Tested on Python 3.8.0
# This tool should be used with Legend of Galactic Heroes

# Ver    Date        Author
# v0.1   13.06.2020  Bartlomiej Duda



import os
import sys
import struct



def bd_logger(in_str):
    import datetime
    now = datetime.datetime.now()
    print(now.strftime("%d-%m-%Y %H:%M:%S") + " " + in_str)    
    


def extract_files(in_FILE_path, out_FOLDER_path):
    '''
    Function for extracting data from IKM files
    '''    
    bd_logger("Starting extract_files...")    
    
    in_file = open(in_FILE_path, 'rb')
    
    if not os.path.exists(out_FOLDER_path):
        os.makedirs(out_FOLDER_path)   
        
    ikm_size = os.stat(in_FILE_path).st_size
    
    
    import re
    with open(in_FILE_path, "rb") as f:
        data = f.read()
    
    matches = []                
    curpos = 0                  
    pattern = re.compile(br'OggS')   #TODO --> search "vorbis" and go back
    while True:
        m = pattern.search(data[curpos:])     
        if m is None: break  
        if curpos != 0:
            matches.append(curpos-4) 
        curpos += m.end()              
    
    
    matches.append(ikm_size)
    mat_len = len(matches)

    
    for i in range(mat_len - 1):
        f_offset = matches[i]
        f_size = matches[i+1] - matches[i]
        #print("f_offset: " + str(f_offset) + " f_size: " + str(f_size) )
        
        
        #TODO 
        in_file.seek(f_offset)
        out_data = in_file.read(f_size)
        out_file = open(out_FOLDER_path + str(i+1) + ".ogg", 'wb+')
        out_file.write(out_data)
        out_file.close()
    
    
    
    in_file.close()
    bd_logger("Ending extract_files...")    
    
    
        
    
    
    
def main():
    
    main_switch = 1
    # 1 - data export
  

    if main_switch == 1:
        in_file_path = "C:\\Users\\Arek\\Desktop\\BGM_000.ikm"
        out_folder_path = "C:\\Users\\Arek\\Desktop\\BGM_000_ikm_out\\"
        extract_files(in_file_path, out_folder_path)
        
        
        
    else:
        print("Wrong option selected!")
    
    
    bd_logger("End of main...")    
    
    
    
main()