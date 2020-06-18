# -*- coding: utf-8 -*-

# Tested on Python 3.8.0
# This tool should be used with Sonic Unleashed (Java)

# Ver    Date        Author                                 Comment
# v0.1   14.06.2020  Bartlomiej Duda                        -
# v0.2   16.06.2020  Bartlomiej Duda                        -
# v0.3   17.06.2020  Bartlomiej Duda                        -
# v0.4   17.06.2020  Bartlomiej Duda                        -
# v0.5   18.06.2020  Bartlomiej Duda                        -
# v0.6   18.06.2020  Bartlomiej Duda / Leia Ivon Flame      Added support for dataIGP


import os
import sys
import struct
import lzma



def bd_logger(in_str):
    import datetime
    now = datetime.datetime.now()
    print(now.strftime("%d-%m-%Y %H:%M:%S") + " " + in_str)    
    


def get_MIME_extension(file_type):
    '''
    Function for getting extension for MIME file from given file type
    '''      
    #decode MIME file type
    #if file_type >= 127 then file is compressed
    
    if file_type in (0, 127): #WAV file
        r_extension = ".wav"    
    elif file_type in (1, 128): #MIDI file
        r_extension = ".midi"
    elif file_type in (2, 129):
        r_extension = ".bin" #binary file
    elif file_type in (4, 131):
        r_extension = ".tex" #textures?        
        
    else:
        print("Unsupported MIME detected: " + str(file_type) )
        r_extension = ".data" #unsupported MIME type
        
    return r_extension






def export_data(in_DATA_path, out_FOLDER_path):
    '''
    Function for exporting data from PACK/SUBPACK files
    '''    
     
    in_file_short = in_DATA_path.split('\\')[-1]
    bd_logger("Starting processing \"" + str(in_file_short) + "\" file...")  

    #detecting if file is pack or subpack 
    subpack_flag = 0 # 0 for default pack file
    try:
        i_in_file_short = len(in_file_short.split('.'))
        if int(i_in_file_short) > 1:
            subpack_flag = 1      
    except:
        print("Error in detecting pack type!")
    
    
    #validity checks
    if in_file_short in ("0", "999", "dataIGPSprites"): # "currently not supported files
        bd_logger("Error 1: This is not supported archive!!! Aborting extraction from \"" + in_file_short + "\" file.")
        return  
    if ("class" in in_file_short) or ("png" in in_file_short):
        bd_logger("Error 2: This is not PACK/SUBPACK archive!!! Aborting extraction from \"" + in_file_short + "\" file.")
        return          
    
    
    if not os.path.exists(out_FOLDER_path):
        os.makedirs(out_FOLDER_path)       
    
    DATA_file = open(in_DATA_path, 'rb')    
    
    
    if in_file_short in "dataIGP": #his is dataIGP file
        num_of_offsets = struct.unpack('<h', DATA_file.read(2))[0]
        
        offset_arr = []
        for i in range(num_of_offsets):
            offset = struct.unpack('<l', DATA_file.read(4))[0]
            offset_arr.append(offset)
            
        file_size = os.stat(in_DATA_path).st_size 
        offset_arr.append(file_size)
        
        base_offset = DATA_file.tell()
            
        for i in range(num_of_offsets-1):
            DATA_file.seek(base_offset + offset_arr[i])
            file_size = offset_arr[i+1] - offset_arr[i]
            data = DATA_file.read(file_size)
            out_file_path = out_FOLDER_path + "\\" + str(i) + ".bin"
            out_file = open(out_file_path, 'wb+')
            out_file.write(data) 
            out_file.close()
        
        

        
        
    
    elif subpack_flag == 1: #this is subpack file
        size_of_offset_table = struct.unpack('<l', DATA_file.read(4))[0] - 4
        num_of_offsets = int(size_of_offset_table / 4)
        
        offset_arr = []
        for i in range(num_of_offsets):
            offset = struct.unpack('<l', DATA_file.read(4))[0]
            offset_arr.append(offset)
            
        for i in range(num_of_offsets - 1):
            file_size = offset_arr[i+1] - offset_arr[i]
            DATA_file.seek(offset_arr[i])
    
    
            file_type = int.from_bytes( DATA_file.read(1), "little")
            
            #decode MIME file type
            extension = get_MIME_extension(file_type)
            if extension == ".data":
                #print("[DEBUG]in_file_short: " + str(in_file_short) + " file_offset: " + str(offset_arr[i]) + " file_name: " + str(i) + extension )  
                pass
            
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
        bd_logger("[SUBPACK] Ending processing \"" + str(in_file_short) + "\" file.")       
    
    
    
    
    
    
    
    else: #this is pack file
    

        
        num_of_files = struct.unpack('<h', DATA_file.read(2))[0]
        num_of_subpacks = struct.unpack('<h', DATA_file.read(2))[0]
        
        
        #read subpacks array
        subpacks_arr = []
        for i in range(num_of_subpacks):
            subpack = struct.unpack('<h', DATA_file.read(2))[0]
            subpacks_arr.append(subpack)
        
    
    
        
    
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
            extension = get_MIME_extension(file_type)
            
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
        bd_logger("[PACK] Ending processing \"" + str(in_file_short) + "\" file.")    
        
    
    
    
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

        #fold_path =  "C:\\Users\\Arek\\Desktop\\GAMELOFT_TEST\\RivalWheels\\"
        fold_path =  "C:\\Users\\Arek\\Desktop\\GAMELOFT_TEST\\Sonic_Unleashed_640x480"
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