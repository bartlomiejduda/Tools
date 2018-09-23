# -*- coding: utf-8 -*-


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



white_list = [ "01-global.group.toc_ex\\00716.LTR", "01-global.group.toc_ex\\00717.LTR", "01-global.group.toc_ex\\00718.LTR"  ]



def text_export(input_folder_path, output_file_path, active_mode):
    print "Start extracting! Please wait, it may take a while!"
    files_ltr_tab = []
    strings_tab = []
    reimport_tab = []
    
    file_id = 0
    string_id = 0
    
    strings_codes_tab = []
    
    extension = 'ltr'
    os.chdir(input_folder_path)
    file_set = glob.glob(r'*.' + extension)
    file_set += glob.glob(r'*\*.' + extension)
    fold = '*\\'
    fold2 = ''
    for i in range(10):
        fold2 += fold
        file_set += glob.glob(fold2 + '*.' + extension)
    for file in file_set:    
        bin_path = os.path.abspath(file)
        files_ltr_tab.append(bin_path)
    files_ltr_tab = sorted(set(files_ltr_tab)) #distinct names
    
    files_ltr_tab_dist_sort = []
    
    
    
    
    if active_mode == "COUNT":
        print "Using counter!"
        counter = 0
        for file_ltr in files_ltr_tab:
            if counter % 5 == 0:
                files_ltr_tab_dist_sort.append(file_ltr)
            counter += 1
            
    elif active_mode == "NORMAL":
        for file_ltr in files_ltr_tab:
            files_ltr_tab_dist_sort.append(file_ltr)
        
    elif active_mode == "WH_LIST": #use white list
        
        for file_ltr in files_ltr_tab:
            file_ltr_split = file_ltr.split('\\')[-2] + "\\" + file_ltr.split('\\')[-1]
            for wh_file in white_list:
                if str(wh_file) == str(file_ltr_split):
                    files_ltr_tab_dist_sort.append(file_ltr)
                    
    else: # ALL strings in all languages
        files_ltr_tab_dist_sort = files_ltr_tab
    
    
    
    
    #Starting extracting texts from LTR files
    for file_ltr in files_ltr_tab_dist_sort:
        
        file_id += 1
        bin_file = open(file_ltr, 'rb')
        bin_file.read(8)
        
        string_code = ''
        string = ''
        while 1: 
            while 1: #getting string code
                byte = struct.unpack('c', bin_file.read(1))[0]
                if byte == '\x00':
                    out_string_code = string_code
                    string_code = ''
                    break
                string_code += byte
                
            while 1: 
                back_offset = bin_file.tell()
                byte = struct.unpack('c', bin_file.read(1))[0]
                if byte != '\x00':
                    bin_file.seek(back_offset)
                    break

            back_offset = bin_file.tell()
            while 1: #getting out string
                byte = struct.unpack('c', bin_file.read(1))[0]
                byte2 = struct.unpack('c', bin_file.read(1))[0]
                if byte == '\x00' and byte2 == '\x00':
                    out_string = string.replace('\n', '<ENT>').replace(';', '<SEM>')
                    string_id += 1
                    reimport_string = str(file_id) + ';' + str(string_id) + ';' + out_string_code + ';' + out_string + ';' + str(back_offset) + ';' + file_ltr + ';'
                    reimport_tab.append(reimport_string)
                    string = ''
                    break
                string += byte  
            
            break_flag = 0
            while 1: #detecting EOF
                back_offset = bin_file.tell()
                strr = bin_file.read(4)
                if strr == "":
                    break_flag = 1
                    break
                else:
                    bin_file.seek(back_offset)
                    break
                
                
            if break_flag == 1: #break main loop
                break
                    
            
        bin_file.close()
        
        
    output_file = open(output_file_path, 'wb+')
    reimport_data_path = output_file_path + '_reimport'
    reimport_data_file = open(reimport_data_path, 'wb+') 
    
    for reim in reimport_tab: #writing output strings to files
        reim_f_name =  str(reim.split(';')[-2].split('\\')[-2]) + '\\' + str(reim.split(';')[-2].split('\\')[-1])
        print "Extracted string " + str(reim.split(';')[2]) + " from file " + str(reim_f_name)
        reim_trans = reim.split(';')[2] + "=" + reim.split(';')[3]
        reimport_data_file.write(reim + '\x0D' + '\x0A')
        output_file.write(reim_trans + '\x0D' + '\x0A')

    
    output_file.close()
    reimport_data_file.close()
    print "All texts extracted!"
    


def text_import(text_folder_path, text_file_path):
    print "Start importing texts!"
    
    text_file = open(text_file_path, 'rb')
    text_import_file = open(text_file_path + '_reimport', 'rb')
    cnt_print = 0
    texts_arr = []
    texts_import_arr = []
    
    for line in text_file:
        texts_arr.append(line)
        
    for line in text_import_file:
        texts_import_arr.append(line)
        
    offset_arr = []
    file_path_arr = []
    for i in range(len(texts_arr)):
        offset_arr.append(texts_import_arr[i].split(';')[-3])
        file_path_arr.append(texts_import_arr[i].split(';')[-2])
    
    
    
    for i in range(len(texts_arr)):
        translated_text = texts_arr[i].split('=')[-1]
        not_translated_text = texts_import_arr[i].split(';')[-4]
        ltr_file_path = texts_import_arr[i].split(';')[-2]
        ltr_file = open(ltr_file_path, 'rb')
        converted_not_translated_text = (convert_to_UTF16(not_translated_text.rstrip('\x0D\x0A')
                                                            .replace('<ENT>', '\n')
                                                            .replace('<SEM>', ';')
                                                            ) 
                                                            .replace('\xC5\x00\xBB\x00', '\xC1\x00') 
                                                            .replace('\xC3\x00\x93\x00', '\xD3\x00')                    
                                                            .replace('\xC5\x00\x81\x00', '\xDC\x00') 
                                                            .replace('\xC4\x00\x86\x00', '\xD6\x00') 
                                                            .replace('\xC4\x00\x98\x00', '\xC9\x00') 
                                                            .replace('\xC5\x00\x9A\x00', '\xDA\x00') 
                                                            .replace('\xC4\x00\x84\x00', '\xC4\x00') 
                                                            .replace('\xC5\x00\xB9\x00', '\xCB\x00') 
                                                            .replace('\xC5\x00\x83\x00', '\xC0\x00') 
                                                                                                             
                                                                                                             
                                                            .replace('\xC5\x00\xBC\x00', '\xE1\x00') 
                                                            .replace('\xC3\x00\xB3\x00', '\xF3\x00') 
                                                            .replace('\xC5\x00\x82\x00', '\xFC\x00') 
                                                            .replace('\xC4\x00\x87\x00', '\xF6\x00') 
                                                            .replace('\xC4\x00\x99\x00', '\xE9\x00') 
                                                            .replace('\xC5\x00\x9B\x00', '\xFA\x00') 
                                                            .replace('\xC4\x00\x85\x00', '\xE4\x00') 
                                                            .replace('\xC5\x00\xBA\x00', '\xEB\x00') 
                                                            .replace('\xC5\x00\x84\x00', '\xE0\x00') )
        
        
        converted_translated_text = (convert_to_UTF16(translated_text.rstrip('\x0D\x0A')
                                                            .replace('<ENT>', '\n')
                                                            .replace('<SEM>', ';')
                                                            ) 
                                                            .replace('\xC5\x00\xBB\x00', '\xC1\x00') 
                                                            .replace('\xC3\x00\x93\x00', '\xD3\x00')                    
                                                            .replace('\xC5\x00\x81\x00', '\xDC\x00') 
                                                            .replace('\xC4\x00\x86\x00', '\xD6\x00') 
                                                            .replace('\xC4\x00\x98\x00', '\xC9\x00') 
                                                            .replace('\xC5\x00\x9A\x00', '\xDA\x00') 
                                                            .replace('\xC4\x00\x84\x00', '\xC4\x00') 
                                                            .replace('\xC5\x00\xB9\x00', '\xCB\x00') 
                                                            .replace('\xC5\x00\x83\x00', '\xC0\x00') 
                                                                                                             
                                                                                                             
                                                            .replace('\xC5\x00\xBC\x00', '\xE1\x00') 
                                                            .replace('\xC3\x00\xB3\x00', '\xF3\x00') 
                                                            .replace('\xC5\x00\x82\x00', '\xFC\x00') 
                                                            .replace('\xC4\x00\x87\x00', '\xF6\x00') 
                                                            .replace('\xC4\x00\x99\x00', '\xE9\x00') 
                                                            .replace('\xC5\x00\x9B\x00', '\xFA\x00') 
                                                            .replace('\xC4\x00\x85\x00', '\xE4\x00') 
                                                            .replace('\xC5\x00\xBA\x00', '\xEB\x00') 
                                                            .replace('\xC5\x00\x84\x00', '\xE0\x00') )
        
        
        text_offset = offset_arr[i]
        ltr_file = open(ltr_file_path, 'rb')
        ltr_file.seek(int(text_offset))
        
        while 1:
            byte = struct.unpack('c', ltr_file.read(1))[0]
            byte2 = struct.unpack('c', ltr_file.read(1))[0]
            if byte == '\x00' and byte2 == '\x00':   
                end_offset = ltr_file.tell() -2
                read_length = end_offset - int(text_offset)
                break
            
        ltr_file.seek(0)
        ltr_part1 = ltr_file.read(int(text_offset))
        ltr_file.seek(end_offset)
        ltr_part2 = ltr_file.read()
        ltr_file.close()
        
        new_ltr_file = open(ltr_file_path + '_new', 'wb+')
        cnt_print += 1
        print str(cnt_print) + ') ' + 'Replacing at offset ' + str(text_offset) + ' in file ' + ltr_file_path
        new_ltr_file.write(ltr_part1 + converted_translated_text + ltr_part2)
        new_ltr_file.close()
        
        
        new2_ltr_file = open(ltr_file_path + '_new2', 'wb+')
        new_ltr_size = os.stat(ltr_file_path + '_new').st_size
        new_ltr_file = open(ltr_file_path + '_new', 'rb')
        head = new_ltr_file.read(4)
        new_ltr_file.read(4)
        rest = new_ltr_file.read()
        len_rest = len(rest)
        new_ltr_file.close()
        
        new2_ltr_file.write(head + struct.Struct("<l").pack(len_rest) + rest)
        new2_ltr_file.close()
        
        shutil.move(ltr_file_path + '_new', ltr_file_path)
        shutil.move(ltr_file_path + '_new2', ltr_file_path)
        
        num_arr = []
        for i, item in enumerate(file_path_arr):
            if item == ltr_file_path:
                num_arr.append(i)
        
        for i in range(len(offset_arr)):
            if i in num_arr:
                diff = len(converted_translated_text) - len(converted_not_translated_text)
                offset_arr[i] = str(int(offset_arr[i]) + diff)
        
        
        
        
    text_file.close()
    text_import_file.close()
    print 'Import finished!'


def convert_to_UTF16(input_string):
    out_str = ''
    for char in input_string:
        out_str += char + '\x00'
    return out_str

	
	
	

#TEXT EXPORT
active_mode = "NORMAL"
input_folder_path = 'D:\\Medievil_Resurrection_USA\\gamedata.bin_extract\\'   
output_file_path = 'C:\\Users\\User\\Desktop\\out.ini'  #put here output ini file
text_export(input_folder_path, output_file_path, active_mode)



#TEXT IMPORT
#text_folder_path = 'D:\\Medievil_Resurrection_USA\\gamedata.bin_extract\\'   
#text_file_path = 'C:\\Users\\User\\Desktop\\out.ini'  
#text_import(text_folder_path, text_file_path)








