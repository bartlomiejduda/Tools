# -*- coding: utf-8 -*-

# Tested on Python 3.8.0
# This tool should be used with Silent Hill: Orphan (Java)

# Ver    Date        Author
# v0.1   17.04.2020  Bartlomiej Duda
# v0.2   17.04.2020  Bartlomiej Duda




VERSION_NUM = "v0.2"

import os
import sys
import struct



def bd_logger(in_str):
    import datetime
    now = datetime.datetime.now()
    print(now.strftime("%d-%m-%Y %H:%M:%S") + " " + in_str)    
    


def export_bin(in_BIN_filepath, out_folder_path):
    '''
    Function for exporting data from BIN files
    '''    
    bd_logger("Starting export_bin...")    
    
    bin_file = open(in_BIN_filepath, 'rb')
    
    num_of_chunks = struct.unpack('b', bin_file.read(1))[0]
    print("num_of_chunks: " + str(num_of_chunks) )
    
    
    #read chunks
    for i in range(num_of_chunks):
        chunk_name_length = struct.unpack('>b', bin_file.read(1))[0]
        chunk_name = bin_file.read(chunk_name_length).decode("utf8")
        #print( str(i+1) + ") chunk_name: " + chunk_name)
        data_size = struct.unpack('>h', bin_file.read(2))[0]
        
        if data_size == 0:
            continue
        else:
            data = bin_file.read(data_size)
            out_path = out_folder_path + "\\" + chunk_name.replace("/", "\\") 
            print(str(i+1) + ") out: " + out_path)
            
            if not os.path.exists(os.path.dirname(out_path)):
                try:
                    os.makedirs(os.path.dirname(out_path))
                except:
                    pass
            
            #write data        
            out_file = open(out_path, 'wb+')
            out_file.write(data)
            out_file.close()
            
   
    
    bin_file.close()
    bd_logger("Ending export_bin...")    
    
    
    
    
def main():
    
    main_switch = 3
    # 1 - bin export 
    # 2 - all bins export
    # 3 - all bins export to the same folder
    
    
    bin_arr = [ "0.bin", "1.bin", "2.bin", "3.bin", "4.bin", "5.bin", "6.bin", "7.bin", "8.bin", "9.bin", "a.bin", "b.bin", "c.bin", "d.bin", "e.bin", "f.bin" ] 
    bin_fold = "C:\\Users\\Arek\\Desktop\\Silent_Hill_Orphan_SPOL\\JAR_out\\chunks\\"
    
    
    if main_switch == 1:
        p_in_BIN_filepath = "C:\\Users\\Arek\\Desktop\\Silent_Hill_Orphan_SPOL\\JAR_out\\chunks\\0.bin"
        p_out_folder_path = "C:\\Users\\Arek\\Desktop\\Silent_Hill_Orphan_SPOL\\JAR_out\\chunks\\0.bin_out"
        export_bin(p_in_BIN_filepath, p_out_folder_path)
        
    elif main_switch == 2:
        for f_bin in bin_arr:
            bin_path = bin_fold + f_bin 
            out_path = bin_fold + f_bin + "_out"
            export_bin(bin_path, out_path)   
            
    elif main_switch == 3:
        for f_bin in bin_arr:
            bin_path = bin_fold + f_bin 
            out_path = bin_fold + "OUT"
            export_bin(bin_path, out_path) 

            
    else:
        print("Wrong option selected!")
        
        
    
    bd_logger("End of main...")    
    
    
    
main()