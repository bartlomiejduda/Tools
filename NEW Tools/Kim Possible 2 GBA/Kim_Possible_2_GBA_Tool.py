# -*- coding: utf-8 -*-

# Tested on Python 3.7.3

# Ver    Date        Name
# v1.0   30.04.2019  Bartlomiej Duda
# v1.1   01.05.2019  Bartlomiej Duda
# v1.2   04.05.2019  Bartlomiej Duda
# v1.3   11.05.2019  Bartlomiej Duda
# v1.4   12.05.2019  Bartlomiej Duda
# v1.5   12.05.2019  Bartlomiej Duda

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
                      "1F": "?"
                      
                      #"01": "!",    "03": "03",   "06": "06",   "0D": "-",   "10": "10",   
                      #"11": "11",   "12": "12",   "13": "13",   "14": "14",  "15": "15",
                      #"1A": ":",   "16": "16",   "17": "17",
                      #"64": "64",   "71": "71",   "80": "80",   "B3": "B3",    "B4": "B4"
                      
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
	
        #for key, val in rev_mapping_dictionary.items():              #ex. 'a'   --> 41
            #if key == "" or key == " ":
                #continue
	    ##print('key: ' + key + ' val: ' + val)
            #result_text += char.replace(key, "\\" + val + " ")
	    #print('input_text: ' + input_text)
	    
	#input_text = re.sub('<.*>', conv_my_replace, input_text)    #ex. <06>  --> 06
    return hex_bytes
    

    
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
                    s_string += convert_byte_to_text(byte + byte2)
                    #print("s_string: " + s_string)
                    break
                elif byte2 == "FC": #this is space
                    s_string += convert_byte_to_text(byte + byte2) #space has 2 chars
                    
            else:
                s_string += convert_byte_to_text(byte)
        string_array.append(s_string)
    
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
 
def count_bytes(input_byte_string):
    counter = 0
    for char in input_byte_string:
        counter += 1
    return counter

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
	
	curr_offset = base_text_offset
	for i in range(num_of_pointers):
	    gba_file_out.seek(curr_offset)
	    print('curr_offset: ' + str(curr_offset))
	    bytes_identifiers = convert_text_to_bytes(identifier_arr[i])
	    gba_file_out.write(bytes_identifiers)
	    curr_offset += count_bytes(bytes_identifiers)
	    #print('add1: ' + str(count_bytes(bytes_identifiers)))
	    bytes_string = convert_text_to_bytes(string_arr[i])
	    gba_file_out.write(bytes_string)
	    curr_offset += count_bytes(bytes_string)
	    
	    #gba_file.read(1)
	    #curr_offset = gba_file.tell() - 1
	    
	    #curr_offset += (gba_file.tell() - curr_offset)
	    #print('roznica: ' + str(gba_file.tell() - curr_offset))
	    #print(convert_text_to_bytes(string_arr[i]))
	    #print(string_arr[i])
	    
	    
	
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




