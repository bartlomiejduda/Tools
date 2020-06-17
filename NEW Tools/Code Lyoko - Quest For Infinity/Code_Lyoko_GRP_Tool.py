# -*- coding: utf-8 -*-

# Tested on Python 3.8.0
# This tool should be used with Code Lyoko: Quest for Infinity

# Ver    Date        Author
# v0.1   17.06.2020  Bartlomiej Duda



import os
import sys
import struct



def bd_logger(in_str):
    import datetime
    now = datetime.datetime.now()
    print(now.strftime("%d-%m-%Y %H:%M:%S") + " " + in_str)    
    


def export_grp(in_GRP_path, out_FOLDER_path):
    '''
    Function for exporting text from GRP files
    '''    
    bd_logger("Starting export_grp...")    
    
    grp_file = open(in_GRP_path, 'rb')
    
    if not os.path.exists(out_FOLDER_path):
        os.makedirs(out_FOLDER_path)      
    
    
    #read header 
    num_of_files = struct.unpack('<h', grp_file.read(2))[0]
    unk1 = struct.unpack('<h', grp_file.read(2))[0]
    
    #read offset/size table 
    offset_arr = []
    size_arr = []
    for i in range(num_of_files):
        file_size = struct.unpack('<l', grp_file.read(4))[0]
        curr_offset = grp_file.tell()
        file_offset = struct.unpack('<l', grp_file.read(4))[0]
        offset_arr.append(file_offset)
        size_arr.append(file_size)
        
        
    #read and then save data
    for i in range(num_of_files):
        grp_file.seek(offset_arr[i])
        data = grp_file.read(size_arr[i])
        out_path = out_FOLDER_path + "\\" + str(i) + ".bin"
        out_file = open(out_path, "wb+")
        out_file.write(data)
        out_file.close()
        print("Extracted file: " + out_path)
    
    
    
    
    grp_file.close()
    bd_logger("Ending export_grp...")    
    

    
def main():
    
    main_switch = 1
    # 1 - data export 
    
    
    if main_switch == 1:
        in_path = "C:\\Users\\Arek\\Desktop\\MUSIC.GRP"
        out_path = "C:\\Users\\Arek\\Desktop\\MUSIC_GRP_OUT\\"
        export_grp(in_path, out_path)

    else:
        print("Wrong option selected!")
    
    
    bd_logger("End of main...")    
    
    
    
main()