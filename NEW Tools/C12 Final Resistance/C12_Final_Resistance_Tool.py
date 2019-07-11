# -*- coding: utf-8 -*-

# Tested on Python 3.7.3

# Ver    Date        Name
# v1.0   29.06.2019  Bartlomiej Duda
# v1.1   11.07.2019  Bartlomiej Duda


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



def text_export(input_textfile_path, output_textfile_path):
    print ("Starting C12 text export...")
    
    str_arr = []
    ident_arr = []
    text_file = open(input_textfile_path, 'rt')
    out_file = open(output_textfile_path, 'wt+')
    
    for line in text_file:
        if line[0] == ';':
            continue
        
        ident_splitted = line.split(':')[:2]
        ident = ':'.join(ident_splitted) + ':'
        
        string = line.split(ident)[-1]
        #print (ident + string)
        str_arr.append(string)
        ident_arr.append(ident)
        
    for i in range(len(str_arr)):
        string = str_arr[i]
        if string[0] == '[':
            out_file.write(str_arr[i])
        else:
            out_file.write(ident_arr[i] + '=' + str_arr[i])
        
    text_file.close()
    out_file.close()
    
    print ("C12 text has been exported!")
    

def text_import(input_textfile_path, output_textfile_path):
    print ("Starting C12 text import...")
    
    ini_file = open(input_textfile_path, 'rt')
    txt_file = open(output_textfile_path, 'wt+')   
    
    lines_arr = []
    
    for line in ini_file:
        
        ident = line.split('=')[0]
        string = ''.join(line.split('=')[1:])
        
        #if ident == '23:1210:':
            #string = '=' + string
            
        string = (
              string.replace('Ż', '\xC1') #Ż --> 
                    .replace('Ó', '\xD3') #Ó --> 
                    .replace('Ł', '\xDC') #Ł --> 
                    .replace('Ć', '\xD6') #Ć --> 
                    .replace('Ę', '\xC9') #Ę --> 
                    .replace('Ś', '\xDA') #Ś --> 
                    .replace('Ą', '\xC4') #Ą --> 
                    .replace('Ź', '\xCB') #Ź --> 
                    #.replace('Ń', '\xD1') #Ń --> 
                    
                    
                    .replace('ż', '\xE1') #ż --> 
                    .replace('ó', '\xF3') #ó --> 
                    .replace('ł', '\xFC') #ł --> 
                    .replace('ć', '\xF6') #ć --> 
                    .replace('ę', '\xE9') #ę --> 
                    .replace('ś', '\xFA') #ś --> 
                    .replace('ą', '\xE4') #ą --> 
                    .replace('ź', '\xEB') #ź --> 
                   # .replace('ń', '\xF1') #ń -->   

                    )
            
        lines_arr.append(ident + string)    
        
    for line in lines_arr:
        txt_file.write(line)
        
        
    ini_file.close()
    txt_file.close()
    print('C12 text has been imported!')



def text_out(input_MWD_file, output_txt_file, text_start_offset, text_end_offset):
    print ("Starting C12 text out...")
    
    MWD_file = open(input_MWD_file, 'rb')
    txt_file = open(output_txt_file, 'wb+')   
    
    text_len = text_end_offset - text_start_offset
    MWD_file.seek(text_start_offset)
    text_data = MWD_file.read(text_len)
    txt_file.write(text_data)
    
    MWD_file.close()
    txt_file.close()
    print("C12 text out has been finished.")
    
    
def text_in(input_MWD_file, input_txt_file, text_start_offset, text_end_offset):
    print ("Starting C12 text in...")
    
    MWD_file = open(input_MWD_file, 'rb')
    txt_file = open(output_txt_file, 'rb') 
    MWD_file_new = open(input_MWD_file + '_NEW', 'wb+')
    
    
    MWD_file.close()
    txt_file.close()
    MWD_file_new.close()
    print("C12 text in has been finished.")    

#TEXT EXPORT (converts TXT to INI)
#p_input_textfile_path = 'C:\\Users\\Arek\\Desktop\\C12_FILES\\out_PAL.txt'   
#p_output_textfile_path = 'C:\\Users\\Arek\\Desktop\\C12_FILES\\out_PAL.ini'  #put here output ini filepath
#text_export(p_input_textfile_path, p_output_textfile_path)



#TEXT IMPORT (converts INI to TXT)
#p_input_INI_file = 'C:\\Users\\Arek\\Spolszczenia\\C12_Final_Resistance_OmegaT\\target\\C12_tekst_OUT.ini'  
#p_output_TXT_file = 'C:\\Users\\Arek\\Spolszczenia\\C12_Final_Resistance_OmegaT\\target\\C12_tekst_OUT.txt'
#text_import(p_input_INI_file, p_output_TXT_file)


#TEXT OUT (copies text from PROJFILE.MWD to TXT file)
#p_input_MWD_file = 'C:\\Users\\Arek\\Desktop\\C12_FILES\\PROJFILE.MWD'
#p_output_txt_file = 'C:\\Users\\Arek\\Desktop\\C12_FILES\\out.txt'
#p_text_start_offset = 489472 
#p_text_end_offset = 555657
#text_out(p_input_MWD_file, p_output_txt_file, p_text_start_offset, p_text_end_offset)


#TEXT IN (copies text from TXT file to PROJFILE.MWD)
p_input_MWD_file = 'C:\\Users\\Arek\\Desktop\\C12_FILES\\PROJFILE.MWD'
p_input_txt_file = 'C:\\Users\\Arek\\Desktop\\C12_FILES\\out.txt'
p_text_start_offset = 489472 
p_text_end_offset = 555657
text_in(p_input_MWD_file, p_input_txt_file, p_text_start_offset, p_text_end_offset)