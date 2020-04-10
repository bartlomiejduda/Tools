# -*- coding: utf-8 -*-

# Tested on Python 3.8.0
# This tool should be used with Silent Hill: Shattered Memories (PSP)

# Ver    Date        Author
# v0.1   23.02.2020  Bartlomiej Duda


VERSION_NUM = "v0.1"

import os
import sys
import struct

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


#read ARC hash
p_in_ARC_filepath = "c:\\Users\\Arek\\Desktop\\Silent_Hill_SM\\DATA.ARC"
read_ARC_hash(p_in_ARC_filepath)