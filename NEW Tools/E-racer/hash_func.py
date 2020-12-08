# -*- coding: utf-8 -*-

'''
Copyright © 2020  Bartłomiej Duda
License: GPL-3.0 License 
'''


# Program tested on Python 3.7.0
# It should be used with E-Racer (PC)

# Ver    Date        Author               Comment
# v0.1   08.12.2020  Bartlomiej Duda      -
# v0.2   08.12.2020  Bartlomiej Duda      -

import os
import sys
import struct
import datetime


def bd_logger(in_str):
    '''
    Function for logging debug messages
    '''   
    now = datetime.datetime.now()
    print(now.strftime("%d-%m-%Y %H:%M:%S") + " " + in_str)    
    

def calculate_eracer_hash(in_filename):
    len_filename = len(in_filename)
    curr_char_IDX = 0
    hash_part_LAST = 0
    curr_char = ""
    hash_part3 = 0
    
    for i in range(len_filename-1):
        if curr_char_IDX < len_filename:
            curr_char = int(ord(in_filename[i]))
            part_hash1 = curr_char + curr_char_IDX 
            part_hash2 = curr_char + 7
            
            while 1:
                hash_part3 = part_hash1 * part_hash2 * (int(ord(in_filename[curr_char_IDX])) + 19) * (int(ord(in_filename[curr_char_IDX])) + curr_char_IDX)
                curr_char_IDX += 1
                hash_part_LAST += hash_part3
                if curr_char_IDX >= len_filename:
                    break
                
            curr_char_IDX = i
        curr_char_IDX += 1
    
    conv = int(str(hex(hash_part_LAST))[-8:], 16) # workaround!
    hash_part_LAST = conv
     
    OUT_HASH = hash_part_LAST % 0xEE6B2800
    return OUT_HASH
    
    
def compare_hash(in_filename, in_hash, in_hash_should_be):
    is_match = "NO"
    if in_hash == in_hash_should_be:
        is_match = "YES"
    print(in_filename + "--> " + "in_hash: " + str(hex(in_hash)) + " should_be: " + str(hex(in_hash_should_be)) + " is_match: " + is_match)

def print_dec_hex(in_char_idx, name, in_value):
    print(str(in_char_idx) + ") " + name + "_DEC: " + str(in_value) + " " + name + "_HEX: " + str(hex(in_value)))
    
    
def main():
    
    main_switch = 2
    # 1 - hash checking
    # 2 - bin_hash dump analysis
    
    
    
    if main_switch == 1:
        hash_dump_file = open("eracer_hash_dump.txt", "rt")
        hash_count = 0
        hash_arr = []
        name_arr = []
        for line in hash_dump_file:
            hash_count += 1
            hash_entry = int(line.split("=")[0], 16)
            name_entry = line.split("=")[1].rstrip("\n")
            
            res_hash = calculate_eracer_hash(name_entry)
            #compare_hash(name_entry, res_hash, hash_entry)  # use this for checking hashes
            
            hash_arr.append(hash_entry)
            name_arr.append(name_entry)
        
    
    
    
    elif main_switch == 2:
    
        hash_bin_file = open("hash_dump.bin", "rb")   # hash index dump from XFS file, use this only for debug!
        bin_size = os.path.getsize("hash_dump.bin")
        
        num_of_entries = int(bin_size / 8)
        offset_arr = []
        
        for i in range(num_of_entries):
            hash_b_entry = hex(struct.unpack("<L", hash_bin_file.read(4))[0])
            offset_b_entry = struct.unpack("<L", hash_bin_file.read(4))[0]
            offset_arr.append(offset_b_entry)
            
            #print(str(i+1) + ") " + "hash: " + str(hash_b_entry) + "\toffset: " + str(offset_b_entry) )
           
           
        offset_arr.sort()
         
        
        for entry in offset_arr:
            print(entry)
            
            
    else:
        print("Wrong option selected!")
                                       
                                       
    
        
        
        
    
    bd_logger("End of main...")    
    
    
    
main()