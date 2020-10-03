# -*- coding: utf-8 -*-

# Tested on Python 3.8.0
# This tool should be used with Spy Bot Chronicles (iphone)

# Ver    Date        Author
# v0.1   04.10.2020  Bartlomiej Duda



import os
import sys
import struct



def bd_logger(in_str):
    import datetime
    now = datetime.datetime.now()
    print(now.strftime("%d-%m-%Y %H:%M:%S") + " " + in_str)    
    


def export_pak(in_PAK_filepath, out_folder_path):
    '''
    Function for exporting data from PAK files
    '''    
    bd_logger("Starting export_pak...")    
    
    pak_file = open(in_PAK_filepath, 'rb')
    
    
    pak_file.read(3) #read magic 
    pak_file.read(3) #read unknown
    num_of_entries = struct.unpack(">H", pak_file.read(2))[0]
    pak_file.read(4)
    #print("Number of files: " + str(num_of_entries) )
    
    
    
    for i in range(num_of_entries):
        pak_file.read(8)  #read entry
        curr_off = pak_file.tell()


    for i in range(num_of_entries):
        curr_off = pak_file.tell()
        comp_size = struct.unpack(">L", pak_file.read(4))[0]
        uncomp_size = struct.unpack(">L", pak_file.read(4))[0]
        
        file_data = pak_file.read(comp_size)
        
        #print(str(i+1) + ") " + "\tcomp_size: " + str(comp_size) + " \tuncomp_size: " + str(uncomp_size) + "\t curr_off: " + str(curr_off) )
        
        file_ext = ""
        sign = ""
        try:
            sign = file_data[1:4].decode("utf8")
        except:
            pass

        
        if sign == "PNG":
            file_ext = ".png"
        elif comp_size == uncomp_size:
            file_ext = ".bin"
        else:
            file_ext = ".comp"
            
        out_path = out_folder_path + "file" + str(i+1) + file_ext 
        print(out_path)
        
        
        out_file = open(out_path, 'wb+')
        out_file.write(file_data)
        out_file.close()

            
   
    
    pak_file.close()
    bd_logger("Ending export_pak...")    
    
    
    
    
def main():
    
    main_switch = 1
    # 1 - pak export 
 
    
    if main_switch == 1:
        p_in_PAK_filepath = "C:\\Users\\Arek\\Desktop\\spybot.pak"
        p_out_folder_path = "C:\\Users\\Arek\\Desktop\\pak_out\\"
        export_pak(p_in_PAK_filepath, p_out_folder_path)
    
    else:
        print("Wrong option selected!")
        
        
    
    bd_logger("End of main...")    
    
    
    
main()