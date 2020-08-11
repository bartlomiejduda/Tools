# -*- coding: utf-8 -*-

# Tested on Python 3.8.0
# This tool should be used with The Touryst

# Ver    Date        Author
# v0.1   11.08.2020  Bartlomiej Duda


import os
import sys
import struct



def bd_logger(in_str):
    import datetime
    now = datetime.datetime.now()
    print(now.strftime("%d-%m-%Y %H:%M:%S") + " " + in_str)    
    


def get_loc_table(in_arr, in_file):
    '''
    Function for getting LOC table
    '''      
    #bd_logger("Starting get_loc_table...")  
    
    
    in_file.seek(108)
    c_str = ""
    #str_arr = []
    j = 0
    
    for i in range(5175):
    
        c_char = struct.unpack("c", in_file.read(1))[0].decode("utf8")
        
        
        if ord(c_char) == 0:
            j += 1
            #print("i=" + str(i) + ", j=" + str(j) + " " + c_str)
            in_arr.append(c_str)
            c_str = ""
        else:
            c_str += c_char
            
        in_file.read(7)
    
    
    
    #bd_logger("Ending get_loc_table...")  




def export_text(in_file_path, out_folder_path):
    '''
    Function for exporting texts from LOC files
    '''    
    bd_logger("Starting export_text...")    
    
    in_file = open(in_file_path, 'rb')
    
    #get loc table
    loc_table = []
    get_loc_table(loc_table, in_file)
    
    
    #save loc table
    loc_out = open(out_folder_path + "\\loc_table_out.txt", "wt+")
    for loc_name in loc_table:
        loc_out.write(loc_name + "\n")
    loc_out.close()
    
    
    #read offsets table
    in_file.seek(41496)
    
    for i in range(783):
        offset = struct.unpack("<L", in_file.read(4))[0]
        print(str(i+1) + ") " + str(offset))
    
   
   
    
    in_file.close()
    bd_logger("Ending export_text...")    
    
    
    
    
def main():
    
    main_switch = 1
    # 1 - loc export 
  
    if main_switch == 1:
        p_in_file_path = "C:\\Users\\Arek\\Desktop\\localize.loc"
        p_out_folder_path = "C:\\Users\\Arek\\Desktop\\localize.loc_OUT"
        export_text(p_in_file_path, p_out_folder_path)

            
    else:
        print("Wrong option selected!")
        
        
    
    bd_logger("End of main...")    
    
    
    
main()