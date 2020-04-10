# -*- coding: utf-8 -*-

# Tested on Python 3.8.0
# This tool should be used with Silent Hill: Shattered Memories (PSP)

# Ver    Date        Author
# v0.1   23.02.2020  Bartlomiej Duda
# v0.2   10.04.2020  Bartlomiej Duda
# v0.3   10.04.2020  Bartlomiej Duda


VERSION_NUM = "v0.3"

import os
import sys
import struct
import zlib

def calc_arc_hash(in_str):
    hash_c = 0
    for i in range(len(in_str)):
        hash_c *= 33;
        hash_c ^= ord(in_str[i])
    return int(hash_c)
        

def bd_logger(in_str):
    import datetime
    now = datetime.datetime.now()
    print(now.strftime("%d-%m-%Y %H:%M:%S") + " " + in_str)    
    
    

def read_ARC_hash(in_ARC_filepath):
    bd_logger("Starting read_ARC_hash function...")
    ARC_file = open(in_ARC_filepath, 'rb') 
    ARC_file.read(4)
    num_of_files = struct.unpack('<I', ARC_file.read(4))[0]
    ARC_file.read(8)
    
    hash_arr = []
    for i in range(num_of_files):
        hash_i = struct.unpack('<I', ARC_file.read(4))[0]
        ARC_file.read(12)
        hash_arr.append(hash_i)
        #print(hash_i)
    
    ARC_file.close()
    p_in_str = "boot_4.txd".lower()
    print("in_str: " + p_in_str)
    
    hash_res = calc_arc_hash(p_in_str)
    for hash_a in hash_arr:
        print("Hash_a: " + str(hash_a) + ", Hash_res: " + str(hash_res) )
        if hash_a == hash_res:
            print("Hash found!" + hash_a)
    bd_logger("Ending read_ARC_hash function...")
    
    
    
    
def unpack_ARC(in_ARC_filepath, out_folder_filepath):
    bd_logger("Starting unpack_ARC function...")
    ARC_file = open(in_ARC_filepath, 'rb') 
    off_arr = []
    csize_arr = []    
    
    #reading header
    magic = ARC_file.read(4)
    num_of_files = struct.unpack('<I', ARC_file.read(4))[0]
    data_start_offset = struct.unpack('<I', ARC_file.read(4))[0]
    dummy = ARC_file.read(4)
    
    
    #rading file info
    for i in range(num_of_files):
        CRC = ARC_file.read(4)
        file_offset = struct.unpack('<I', ARC_file.read(4))[0]
        comp_filesize = struct.unpack('<I', ARC_file.read(4))[0]
        uncomp_filesize = ARC_file.read(4)
        off_arr.append(file_offset)
        csize_arr.append(comp_filesize)
    
    
    #reading data    
    for i in range(num_of_files):
        ARC_file.seek(off_arr[i])
        print( str(i+1) + "\\" + str(num_of_files) )
        data = ARC_file.read(csize_arr[i])
        try:
            uncomp_data = zlib.decompress(data)
        except:
            uncomp_data = data
        out_filepath = out_folder_filepath + "\\" + "file" + str(i+1) + ".dat"
        out_file = open(out_filepath, 'wb+') 
        out_file.write(uncomp_data)
        out_file.close()
    
    ARC_file.close()
    bd_logger("Ending unpack_ARC function...")
    
    
def pack_ARC(in_folder_filepath, in_ARC_filepath, out_ARC_filepath): #this function has limited use due to hardcoded values 
    bd_logger("Starting pack_ARC function...")
    
    old_ARC_file = open(in_ARC_filepath, 'rb') 
    new_ARC_file = open(out_ARC_filepath, 'rb') 
    
    #header read
    magic = old_ARC_file.read(4)
    b_num_of_files = old_ARC_file.read(4)
    num_of_files = struct.unpack('<I', b_num_of_files)[0]
    data_offset = old_ARC_file.read(4)
    dummy = old_ARC_file.read(4)
    
    for i in range(num_of_files):
        pass #TODO
    
    
    
    old_ARC_file.close()
    new_ARC_file.close()
    bd_logger("Starting pack_ARC function...")


#read ARC hash
#p_in_ARC_filepath = "c:\\Users\\Arek\\Desktop\\Silent_Hill_SM\\DATA.ARC"
#read_ARC_hash(p_in_ARC_filepath)


#unpack ARC
p_in_ARC_filepath = "C:\\Users\\Arek\\Desktop\\Silent_Hill_SM\\USA_ROM\\DATA.ARC"
p_out_folder_filepath = "C:\\Users\\Arek\\Desktop\\Silent_Hill_SM\\USA_ROM\\data_arc_test"
unpack_ARC(p_in_ARC_filepath, p_out_folder_filepath)


