# -*- coding: utf-8 -*-

# Tested on Python 3.8.0
# This tool should be used with Sonic Unleashed (Java)

# Ver    Date        Author
# v0.1   14.06.2020  Bartlomiej Duda
# v0.2   16.06.2020  Bartlomiej Duda
# v0.3   17.06.2020  Bartlomiej Duda


import os
import sys
import struct
import lzma



def bd_logger(in_str):
    import datetime
    now = datetime.datetime.now()
    print(now.strftime("%d-%m-%Y %H:%M:%S") + " " + in_str)    
    


def export_data(in_DATA_path, out_FOLDER_path):
    '''
    Function for exporting data from DATA files
    '''    
    #bd_logger("Starting export_data...")   
    in_file_short = in_DATA_path.split('\\')[-1]
    
    if not os.path.exists(out_FOLDER_path):
        os.makedirs(out_FOLDER_path)       
    
    DATA_file = open(in_DATA_path, 'rb')
    
    num_of_files = struct.unpack('<h', DATA_file.read(2))[0]
    num_of_subpacks = struct.unpack('<h', DATA_file.read(2))[0]
    
    
    #validity checks
    file_size_err_check = os.stat(in_DATA_path).st_size
    if num_of_files > file_size_err_check:
        bd_logger("Error 1: This is not valid archive!!! Aborting extraction from \"" + in_file_short + "\" file.")
        return
    if in_file_short == "999": # "999" file is an archive list
        bd_logger("Error 2: This is not supported archive!!! Aborting extraction from \"" + in_file_short + "\" file.")
        return        
    
    #read subpacks array
    subpacks_arr = []
    for i in range(num_of_subpacks):
        subpack = struct.unpack('<h', DATA_file.read(2))[0]
        subpacks_arr.append(subpack)
    

    #detecting if file is pack or subpack   (subpack extraction is not supported now)
    try:
        i_in_file_short = len(in_file_short.split('.'))
        if int(i_in_file_short) > 1:
            print("This file \"" + str(in_file_short) + "\" is not pack file. Skipping...")
            return
    except:
        print("Error in detecting pack type!")

    

    #subpack algorithm
    curr_subpack = 0 
    if curr_subpack == num_of_subpacks - 1:
        num_of_files = num_of_files - subpacks_arr[curr_subpack]
    else:
        if num_of_subpacks != 0:
            num_of_files = subpacks_arr[curr_subpack+1] - subpacks_arr[curr_subpack]

        
    
    #save offset table    
    offset_arr = []
    for i in range(num_of_files):
        offset = struct.unpack('<l', DATA_file.read(4))[0]
        offset_arr.append(offset)    
    last_offset = struct.unpack('<l', DATA_file.read(4))[0]
    offset_arr.append(last_offset)
    extension = ""
    
    for i in range(num_of_files):
        
        #save data info
        file_size = offset_arr[i+1] - offset_arr[i]
        DATA_file.seek(offset_arr[i] )
        
        file_type = int.from_bytes( DATA_file.read(1), "little")
        
        #decode MIME file type
        #if file_type >= 127 then file is compressed
        if file_type == 128:
            extension = ".midi"
        elif file_type == 127:
            extension = ".wav"
        else:
            extension = ".bin" #unsupported MIME type
        
        #read data
        if file_type >= 127:
            file_data = lzma.decompress( DATA_file.read(file_size) ) 
        else:
            file_data = DATA_file.read(file_size)
            
        
        out_file_path = out_FOLDER_path + "\\" + str(i) + extension
        out_file = open(out_file_path, 'wb+')
        out_file.write(file_data) 
        out_file.close()

    
    DATA_file.close()
    bd_logger("Ending processing " + str(in_file_short) + " file.")    
    
    
    
    
def main():
    
    main_switch = 2
    # 1 - data export 
    # 2 - data mass export

    
  
    
    if main_switch == 1:
        temp_name = "0"
        p_in_DATA_path = "C:\\Users\\Arek\\Desktop\\Sonic Unleashed\\Sonic_Unleashed_640x480\\" + temp_name 
        p_out_FOLDER_path = "C:\\Users\\Arek\\Desktop\\Sonic Unleashed\\Sonic_Unleashed_640x480\\" + temp_name + "_out"
        export_data(p_in_DATA_path, p_out_FOLDER_path)
        
    if main_switch == 2:    
        fold_path = "C:\\Users\\Arek\\Desktop\\Sonic Unleashed\\Sonic_Unleashed_640x480\\"
        for file in os.listdir(fold_path):
            in_file = os.path.join(fold_path, file)
            if os.path.isdir(in_file):
                pass
            else:
                out_folder = in_file + "_out"
                #print(in_file)
                export_data(in_file, out_folder)
    
            
    else:
        print("Wrong option selected!")
        

    bd_logger("End of main...")    
    
    
    
main()