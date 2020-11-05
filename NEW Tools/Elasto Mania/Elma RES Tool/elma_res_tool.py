# -*- coding: utf-8 -*-

# Tested on Python 3.8.0

# Ver    Date        Author
# v0.1   05.11.2020  Bartlomiej Duda



import os
import sys
import struct
import binascii


def bd_logger(in_str):
    import datetime
    now = datetime.datetime.now()
    print(now.strftime("%d-%m-%Y %H:%M:%S") + " " + in_str)    


from itertools import cycle
def xore(data, key):
    return bytes(a ^ b for a, b in zip(data, cycle(key)))




def unpack_res_file(in_file_path, key_file_path, out_file_path, out_folder_path):
    bd_logger("Starting unpack_res_file...")   
    in_file = open(in_file_path, "rb")
    key_file = open(key_file_path, "rb")
    out_file = open(out_file_path, "wb+")
    
    
    #decode info array
    for i in range(3604):
        data_in = in_file.read(1)
        key_in = key_file.read(1)
        xor_res = xore(data_in, key_in)
        #print("xor_res: " +str(binascii.hexlify(xor_res)))
        out_file.write(xor_res)
    
    key_file.close()
    out_file.close()  
    
    
    #read decoded info array
    out_file = open(out_file_path, "rb")
    
    num_of_files = struct.unpack("<L", out_file.read(4))[0]
    bd_logger("num_of_files: " + str(num_of_files))
    
    
    def bytes_to_str(in_bytes):
        out_str = ""
        for ch in in_bytes:
            if ch == 0:
                return out_str
            else:
                out_str += chr(ch)
        return out_str
    
    if not os.path.exists(out_folder_path):
            os.makedirs(out_folder_path)     
    
    
    for i in range(num_of_files):
        file_name = bytes_to_str(out_file.read(16))
        file_size = struct.unpack("<L", out_file.read(4))[0]
        file_offset = struct.unpack("<L", out_file.read(4))[0]
        
        #print("filename: " + str(file_name) + " file_size: " + str(file_size) + " file_offset: " + str(file_offset))
        
        output_file_path = out_folder_path + file_name
        print(output_file_path)
        
        #read and write data
        in_file.seek(file_offset)
        out_data = in_file.read(file_size)
        
        output_file = open(output_file_path, "wb+")
        output_file.write(out_data)
        output_file.close()
        
        
    
    
    
    
    out_file.close()
    in_file.close()
    bd_logger("Ending unpack_res_file...")   
    
    
    
def main():
    
    main_switch = 1
    # 1 - unpack Elma.res
  

    if main_switch == 1:
        p_in_file_path = "C:\\Users\\Arek\\Desktop\\XOR\\Elma.res"
        p_key_file_path = "C:\\Users\\Arek\\Desktop\\XOR\\key.bin"
        p_out_file_path = "C:\\Users\\Arek\\Desktop\\XOR\\out.bin"
        p_out_folder_path = "C:\\Users\\Arek\\Desktop\\XOR\\out_dir\\"
        unpack_res_file(p_in_file_path, p_key_file_path, p_out_file_path, p_out_folder_path)
        
        
    else:
        print("Wrong option selected!")
    
    
    bd_logger("End of main...")    
    
    
    
main()