# -*- coding: utf-8 -*-


#It was tested on Python 2.7

#This tool was made by Ikskoks for Xentax community.
#Please don't copy this tool to other forums and sites.

#If you like my tool, please consider visit my fanpage https://www.facebook.com/ikskoks/ and site http://ikskoks.pl/


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




def ucm_to_txt(ucm_file_path, text_block_offset, output_folder):
    ucm_file = open(ucm_file_path, 'rb')
    (ucm_path, ucm_name) = os.path.split(ucm_file_path)
    (ucm_short_name, temp2) = os.path.splitext(ucm_name)      
    ucm_file.seek(text_block_offset)
    output_path = output_folder +  ucm_short_name.split('.')[0] + '.txt'
    print output_path    
    txt_file = open(output_path, 'wt+')
    
    while True:
        one = struct.unpack('B', ucm_file.read(1))[0]
        if one != 1: 
            break        
        string_length = struct.unpack('h', ucm_file.read(2))[0]
        ucm_file.read(2)
        string = str(ucm_file.read(string_length))
        txt_file.write(string.replace('\x0D', '').replace('\x0A', ' ') + '\n')
    print 'Text extracted successfully!'
    
    
def ucm_to_txt2(ucm_file_path, text_block_offset, output_folder):
    ucm_file = open(ucm_file_path, 'rb')
    (ucm_path, ucm_name) = os.path.split(ucm_file_path)
    (ucm_short_name, temp2) = os.path.splitext(ucm_name)      
    ucm_file.seek(text_block_offset)
    output_path = output_folder +  ucm_short_name.split('.')[0] + '.txt'
    print output_path    
    txt_file = open(output_path, 'wt+')
    
    while True:
        one = struct.unpack('B', ucm_file.read(1))[0]
        if one < 1: 
            break      
        if one == 1:
            string_length = struct.unpack('h', ucm_file.read(2))[0]
            ucm_file.read(2)
            string = str(ucm_file.read(string_length))
            txt_file.write(string.replace('\x0D', '').replace('\x0A', ' ') + '\n')
        if one > 1:
            pos = ucm_file.tell()
            ucm_file.seek(pos-1)
            string_length = struct.unpack('h', ucm_file.read(2))[0]
            ucm_file.read(2)
            string = str(ucm_file.read(string_length))
            txt_file.write(string.replace('\x0D', '').replace('\x0A', ' ') + '\n')            
            
    print 'Text extracted successfully!'
    
  
  
def tab_size(tab):
    size = 0
    for element in tab:
        size += len(element)
    return size
    
         
        
def txt_to_ucm(path_to_txt, text_block_offset, path_to_ucm):
    txt_file = open(path_to_txt, 'rt')
    tab_strings = []
    num_lines = sum(1 for line in open(path_to_txt))
    for i in range(num_lines):
        line = txt_file.readline().split('\x0A')[0].replace('\xAF', '\xDC').replace('\xD3', '\xD6').replace('\xA3', '\xC0').replace('\xC6', '\xC7').replace('\xCA', '\xCB').replace('\x8C', '\xD9').replace('\xA5', '\xC4').replace('\x8F', '\xC8').replace('\xD1', '\xD4').replace('\xBF', '\xFC').replace('\xF3', '\xF3').replace('\xB3', '\xEC').replace('\xE6', '\xE7').replace('\xEA', '\xE9').replace('\x9C', '\xE0').replace('\xB9', '\xE4').replace('\x9F', '\xE8').replace('\xF1', '\xF1')  
        tab_strings.append(line)
        
    ucm_file = open(path_to_ucm, 'rb')
    ucm_part1 = ucm_file.read(text_block_offset)

    skip_size = 0
    while True:
        one = struct.unpack('B', ucm_file.read(1))[0]
        if one < 1: 
            break     
        if one == 1:
            string_length = struct.unpack('h', ucm_file.read(2))[0]
            ucm_file.read(2)
            string = str(ucm_file.read(string_length))
            skip_size += 5 + string_length  
        if one > 1:
            pos = ucm_file.tell()
            ucm_file.seek(pos-1)
            string_length = struct.unpack('h', ucm_file.read(2))[0]
            ucm_file.read(2)
            string = str(ucm_file.read(string_length))
            skip_size += 5 + string_length 
    
    ucm_file.seek(text_block_offset + skip_size)
    ucm_part2 = ucm_file.read()
    temp_filename = 'a_temp_ucm.ucm'
    out_ucm_path = os.path.dirname(path_to_ucm) + '\\' + temp_filename
    out_ucm_file = open(out_ucm_path, 'wb+')
    out_ucm_file.write(ucm_part1)
    for i in range(len(tab_strings)):
        out_ucm_file.write(struct.Struct("<B").pack(1))
        if (len(tab_strings[i]) < 255):
            out_ucm_file.write(struct.Struct("<B").pack(len(tab_strings[i])))
            out_ucm_file.write('\x00\x00\x00')
        else:
            out_ucm_file.write(struct.Struct("<h").pack(len(tab_strings[i])))
            out_ucm_file.write('\x00\x00')
            
        out_ucm_file.write(tab_strings[i])
    out_ucm_file.write(ucm_part2)
    out_ucm_file.close()
    shutil.move(out_ucm_path, path_to_ucm)
    print 'Text packed successfully!'
    
    
def unpack_all_ucms(game_folder, txt_folder):
    os.chdir(game_folder + '\\levels')
    for file in glob.glob("*.ucm"):
        ucm_path = os.path.abspath(file)

        if "Kopia" in file: continue
        
        ucm_file = open(ucm_path, 'rb')
        file_type = struct.unpack('B', ucm_file.read(1))[0]
        ucm_file.close()
        
        if file_type == 9 or file_type == 10:
            ucm_to_txt(ucm_path, 39461, txt_folder)
            
        if file_type == 5:
            ucm_to_txt2(ucm_path, 39203, txt_folder)
            
        if file_type == 6 or file_type == 7 or file_type == 8:
            ucm_to_txt2(ucm_path, 39459, txt_folder) 
        
     

    print 'All ucm files unpacked successfully!'
    
    
def pack_all_ucms(txt_folder, game_folder):
    os.chdir(txt_folder)
    for file in glob.glob("*.txt"):
        txt_path = os.path.abspath(file)    
        
        if "Kopia" in file: continue
        
        ucm_path = game_folder + 'levels\\' + file.split('.txt')[0] + '.ucm'
        ucm_file = open(ucm_path, 'rb')
        file_type = struct.unpack('B', ucm_file.read(1))[0]
        ucm_file.close()     
        
        if file_type == 9 or file_type == 10:
            txt_to_ucm(txt_path, 39461, ucm_path)
                    
        if file_type == 5:
            txt_to_ucm(txt_path, 39203, ucm_path)
                    
        if file_type == 6 or file_type == 7 or file_type == 8:
            txt_to_ucm(txt_path, 39459, ucm_path)   
            
def replace_chars_in_regular_txt(txt_folder):
    os.chdir(txt_folder)
    for file in glob.glob("*.txt"):
        txt_path = os.path.abspath(file)
        
        temp_path = os.path.dirname(txt_path)
        temp_filename = txt_path.split('\\')[-1].split('.')[0]
        temp_path += '\\' + temp_filename + '_temp.txt'

        temp_file = open(temp_path, 'wb+')
        txt_file = open(txt_path, 'rb')
        
        for line in txt_file:
            line = line.replace('\xAF', '\xDC').replace('\xD3', '\xD6').replace('\xA3', '\xC0').replace('\xC6', '\xC7').replace('\xCA', '\xCB').replace('\x8C', '\xD9').replace('\xA5', '\xC4').replace('\x8F', '\xC8').replace('\xD1', '\xD4').replace('\xBF', '\xFC').replace('\xF3', '\xF3').replace('\xB3', '\xEC').replace('\xE6', '\xE7').replace('\xEA', '\xE9').replace('\x9C', '\xE0').replace('\xB9', '\xE4').replace('\x9F', '\xE8').replace('\xF1', '\xF1')
            temp_file.write(line)
            
        temp_file.close()
        txt_file.close()
        shutil.move(temp_path, txt_path)
        print 'Rapleced chars in ' + txt_path
        



##################################################################################################
    
##UNPACK ALL UCMs
#game_folder = 'd:\\Steam\\steamapps\\common\\Urban Chaos\\' 
#txt_folder = 'C:\\Users\\User\\Desktop\\UC TXT\\'
#unpack_all_ucms(game_folder, txt_folder)
    
##################################################################################################    
    
##REPACK ALL UCMs    
game_folder = 'd:\\Steam\\steamapps\\common\\Urban Chaos\\' 
txt_folder = 'c:\\Users\\User\\Desktop\\Urban Chaos OmegaT\\target\\UCM\\'
pack_all_ucms(txt_folder, game_folder)
    
##################################################################################################
    
    
    
    
## unpack single ucm    
#output_folder = 'C:\\Users\\User\\Desktop\\'
#path_to_game_folder = 'd:\\Steam\\steamapps\\common\\Urban Chaos\\'
#ucm_to_txt(path_to_game_folder, 'FTutor1.ucm', output_folder)



##pack single ucm
#path_to_txt = 'C:\\Users\\User\\Desktop\\FTutor1.txt'
#text_block_offset = 39461
#path_to_ucm = 'd:\\Steam\\steamapps\\common\\Urban Chaos\\levels\\FTutor1.ucm'
#txt_to_ucm(path_to_txt, text_block_offset, path_to_ucm)


##replace chars in txt
#path_to_txt_folder = 'c:\\Users\\User\\Desktop\\Urban Chaos OmegaT\\target\\text\\'
#replace_chars_in_regular_txt(path_to_txt_folder)

