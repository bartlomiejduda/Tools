# -*- coding: utf-8 -*-

# Tested on Python 3.7.3

# Ver    Date        Name
# v1.0   30.04.2019  Bartlomiej Duda
# v1.1   01.05.2019  Bartlomiej Duda
# v1.2   04.05.2019  Bartlomiej Duda
# v1.3   11.05.2019  Bartlomiej Duda
# v1.4   12.05.2019  Bartlomiej Duda
# v1.5   12.05.2019  Bartlomiej Duda
# v1.6   13.05.2019  Bartlomiej Duda

import argparse
import os
import sys
import time
import struct
import binascii
import re
import io
import glob
import codecs
import shutil
from tempfile import mkstemp
from shutil import move
from os import remove, close
from textwrap import wrap

mapping_dictionary = {"41": "a",    "42": "b",    "43": "c",    "44": "d",    "45": "e",
                      "46": "f",    "47": "g",    "48": "h",    "49": "i",    "4A": "j",
                      "4B": "k",    "4C": "l",    "4D": "m",    "4E": "n",    "4F": "o",
                      "50": "p",    "51": "q",    "52": "r",    "53": "s",    "54": "t",
                      "55": "u",    "56": "v",    "57": "w",    "58": "x",    "59": "y",
                      "5A": "z",    
                      
                      "21": "A",    "22": "B",    "23": "C",    "24": "D",    "25": "E",
                      "26": "F",    "27": "G",    "28": "H",    "29": "I",    "2A": "J",
                      "2B": "K",    "2C": "L",    "2D": "M",    "2E": "N",    "2F": "O",
                      "30": "P",    "31": "Q",    "32": "R",    "33": "S",    "34": "T",
                      "35": "U",    "36": "V",    "37": "W",    "38": "X",    "39": "Y",
                      "3A": "Z",
                      
                      "FFFC": " ",  "FFFE": "",   "07": "'",    "0C": ",",    "0E": ".",
                      "1F": "?",
                      
                      "01": "!",    "1A": ":",    "0D": "-",    "63": "ç",    "02": "\"",
                      "06": "&",    "5D": "©",    "10": "0",    "11": "1",    "12": "2",
                      "13": "3",    "14": "4",    "15": "5",    "16": "6",    "17": "7",
                      "18": "8",    "19": "9",    "08": "(",    "09": ")",    
                      "64": "é",    "67": "è"
                      
                      
                      }

rev_mapping_dictionary = {v: k for k, v in mapping_dictionary.items()}

game_chars_dictionary = { "01": "Kim (normal)",    "02": "Kim (disappointed)",   "03": "Kim (eyes down)",
                          "04": "Ron",             "05": "Wade",                 "06": "Kim's mom",
                          "07": "Kim's dad",       "08": "Falsetto Jones",       "09": "Duff Killigan",
                          "0A": "Gemini",          "0B": "Shego",                "0C": "Drakken",
                          "0D": "Kim (sad face)",  "0E": "Weird red head guy",  "0F": "Violet guard",
                          "10": "Betty Director",  "11": "Kim (disgousted)",     "12": "Rufus" }


def convert_byte_to_text(input_byte): #using dictionary to get proper characters 
    try:
        result = mapping_dictionary[input_byte]
        return result
    except:
        return "<" + str(input_byte) + ">"
    
def convert_byte_to_text_short(input_byte): #using dictionary to get proper characters 
        return "<" + str(input_byte) + ">"


def conv_my_replace(match): #replacing match for re.sub
    match = match.group()
    match = match.replace('<', '').replace('>', '') + " "
    return match
    
def convert_text_to_bytes(input_text): #returns bytes to import
    result_text = ""
    sp_counter = 0
    special_char_flag = 0
    special_char = ""
    for char in input_text:
	
        if char == '<':
            special_char_flag = 1
            continue
        if special_char_flag == 1 and char != '>':
            special_char += char
            continue
        if char == '>':
            result_text += special_char + " "
            special_char = ""
            special_char_flag = 0
            continue
	
        try:
            result = rev_mapping_dictionary[char] + " "
            result_text += result
        except:
            result_text += char
        
	
    #result_text = re.sub('<.*>', conv_my_replace, result_text)
    result_text = result_text.replace('FFFC', 'FF FC')
    result_text = result_text.split()
    
    hex_bytes = bytes()
    for hex_item in result_text:
        hex_byte = bytes.fromhex(hex_item)
        hex_bytes += hex_byte
	
    return hex_bytes
    
def count_bytes(input_byte_string):
    counter = 0
    for char in input_byte_string:
        counter += 1
    return counter
    
def get_char_name(input_ident): #using dictionary to get game char names
    try:
        result = "[" + game_chars_dictionary[input_ident] + "]"
        return result
    except:
        return "[None]"

info_array = [ (7237979, 7260511, 492) ]   #  [...(text_offset, pointer_array_offset, num_of_pointers)...]
               


def text_export(input_gba_file, output_file_path, output_reimport_file_path):
    
    print("Text extraction has been started. Please wait, it may take a while!")
    
    base_text_offset = 7237979
    base_pointer_array_offset = 7260511
    num_of_pointers = 492
    pointer_array = []
    string_array = []
    formatted_string_array = [] 
    #text_offset_array = []

    output_file = open(output_file_path, 'wt+')
    output_file_reimport = open(output_reimport_file_path, 'wt+')
    gba_file = open(input_gba_file, 'rb')
    gba_file.seek(base_pointer_array_offset)
    
    #if import_mode == 1:
	#print('Import mode active!')
	#import_data_file = open(output_reimport_file_path.rstrip('.ini') + '_reimport.txt', 'wt+')
    
    for i in range(num_of_pointers):
        gba_file.read(1)
        pointer = struct.unpack('<H', gba_file.read(2))[0]
        gba_file.read(1)
        pointer_array.append(pointer)
	
	#if import_mode == 1:
	    #import_data_file.write(pointer
	
       
    for i in range(num_of_pointers):
        text_offset = base_text_offset + (pointer_array[i] - pointer_array[0])
	#text_offset_array.append(text_offset)
        gba_file.seek(text_offset)
        
        s_string = ""
        while 1: #loop for checking end of line
            byte = gba_file.read(1).hex().upper()

            if byte == "FF":
                byte2 = gba_file.read(1).hex().upper()
                if byte2 == "FE": #end of the string
                    s_string += (byte + byte2)
                    #print("s_string: " + s_string)
                    break
                elif byte2 == "FC": #this is space
                    s_string += (byte + byte2) #space has 2 chars
                    
            else:
                s_string += (byte)
		
        temp = ""
        temp2 = ""
        temp_arr = wrap(s_string[0:18], 2)
        for item in temp_arr: #convert identifiers
                temp += convert_byte_to_text_short(item)
        temp_arr = wrap(s_string[18:], 2)
        for item2 in temp_arr: #convert text
                temp2 += convert_byte_to_text(item2)
        
        str_to_app = temp + temp2.replace('<FF><FC>', " ").replace('<FF><FE>', "")
        print('str_to_app: ' + str(str_to_app))
        string_array.append(str_to_app)
    
    for n_string in string_array: #formatting strings for translating process
        t_string = n_string[36:]
        spl_string = n_string.split(">")
        char_ident = spl_string[7].lstrip("<")
        char_name = get_char_name(char_ident)
        
        r_string = char_name + " " + t_string
        formatted_string_array.append(r_string)
        #print(r_string)
    
    for r_string in formatted_string_array: #writing text for translation
        output_file.write(r_string + '\n')
        
    for s_string in string_array: #writing text for reimport
        output_file_reimport.write(s_string + '\n')
 
 
    
    gba_file.close()
    output_file_reimport.close()
    output_file.close()

    print("All texts extracted!")
 


def text_import(input_gba_file, text_file_path, reimport_file_path):
	
	print("Text reimport has been started. Please wait, it may take a while!")
	
	gba_file = open(input_gba_file, 'rb')
	gba_file_out = open(''.join(input_gba_file.split('.gba')[0:]) + '_out.gba', 'wb+')
	text_file = open(text_file_path, 'rt')
	text_file_reimport = open(reimport_file_path, 'rt')	
	ident_arr = []
	string_arr = []
	identifier_arr = []
	
	gba_data = gba_file.read() 
	gba_file_out.write(gba_data)
	
	
	for line in text_file: #getting text 
	    text = line.split(']')[1:][0][1:]
	    string_arr.append(text)
	    
	for line in text_file_reimport: #getting line identifiers
	    identifiers = line[0:36]
	    identifier_arr.append(identifiers)
	    
	
	base_text_offset = 7237979
	base_pointer_array_offset = 7260511
	num_of_pointers = 492	
	first_pointer_val = 32392
	
	curr_offset = base_text_offset
	new_str_size = 0
	str_sizes_arr = []
	for i in range(num_of_pointers):
	    gba_file_out.seek(curr_offset)
	    #print('curr_offset: ' + str(curr_offset))
	    bytes_identifiers = convert_text_to_bytes(identifier_arr[i])
	    gba_file_out.write(bytes_identifiers)
	    curr_offset += count_bytes(bytes_identifiers)
	    #print('add1: ' + str(count_bytes(bytes_identifiers)))
	    bytes_string = convert_text_to_bytes(string_arr[i]) + bytes.fromhex('FFFE')
	    gba_file_out.write(bytes_string)
	    curr_offset += count_bytes(bytes_string)
	    
	    new_str_size += count_bytes(bytes_identifiers) + count_bytes(bytes_string)
	    str_sizes_arr.append(new_str_size)
	    new_str_size = 0
	
	curr_offset = base_pointer_array_offset   
	add_offset_val = 0
	curr_point_val = first_pointer_val
	for i in range(num_of_pointers):
	    gba_file_out.seek(curr_offset + 1)
	    curr_point_val += add_offset_val
	    print('curr_point_val: ' + str(curr_point_val))
	    point = struct.Struct("<H").pack(curr_point_val)
	    
	    gba_file_out.write(point)
	    add_offset_val = str_sizes_arr[i]
	    curr_offset += 4
	    
	
	gba_file.close()
	gba_file_out.close()
	text_file_reimport.close()
	text_file.close()	
	print("All texts imported!")

#TEXT EXPORT
#p_input_gba_file = "C:\\Users\\Adam\\Desktop\\Tilemolester-0.16\\kim_possible_2.gba"   
#p_output_file_path = "C:\\Users\\Adam\\Desktop\\Tilemolester-0.16\\out_text.ini"  #output ini file
#p_output_reimport_file_path = "C:\\Users\\Adam\\Desktop\\Tilemolester-0.16\\out_text_reimport.ini"  #data used for reimport
#text_export(p_input_gba_file, p_output_file_path, p_output_reimport_file_path)


#TEXT IMPORT
p_input_gba_file = "C:\\Users\\Adam\\Desktop\\Tilemolester-0.16\\kim_possible_2.gba"   
p_text_file_path = "C:\\Users\\Adam\\Desktop\\Tilemolester-0.16\\out_text.ini"  #output ini file
p_reimport_file_path = "C:\\Users\\Adam\\Desktop\\Tilemolester-0.16\\out_text_reimport.ini"  #data used for reimport
text_import(p_input_gba_file, p_text_file_path, p_reimport_file_path)




