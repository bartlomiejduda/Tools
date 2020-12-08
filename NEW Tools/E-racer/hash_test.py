# -*- coding: utf-8 -*-



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
    
    
    #filename = "gui\\gui.ini"
    #res_hash = calculate_eracer_hash(filename)
    #compare_hash(filename, res_hash, 0x502CF816) # gui.ini

    #filename = "control.txt"
    #res_hash = calculate_eracer_hash(filename)
    #compare_hash(filename, res_hash, 0xCBEC3EE6) # control
     
    
    
    
    # new_splash  --> 0xC395F695
    # gui\textures\new_splash.bmp--> in_hash: 0xd52ace95 should_be: 0xc395f695 is_match: NO
    # 0x11C395F695
    
    #filename = "gui\\textures\\new_splash.bmp"
    #res_hash = calculate_eracer_hash(filename)
    #compare_hash(filename, res_hash, 0xC395F695) # new_splash.bmp     
    
    
    
    
    
    
    hash_dump_file = open("eracer_hash_dump.txt", "rt")
    hash_count = 0
    for line in hash_dump_file:
        hash_count += 1
        hash_entry = int(line.split("=")[0], 16)
        name_entry = line.split("=")[1].rstrip("\n")
        
        res_hash = calculate_eracer_hash(name_entry)
        compare_hash(name_entry, res_hash, hash_entry)
        
        
        
    
    bd_logger("End of main...")    
    
    
    
main()