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



def text_export(text_file_path, output_file_path):
    text_file = open(text_file_path, 'rb')
    
    i = 0
    pattern1 = '\x22' + "EN" + '\x22' + ":" + '\x22'
    pattern1_list = []
    offset_tab = []
    string_tab = []
    string_len_tab = []
    
    text = text_file.read()
    for m in re.finditer(pattern1, text):
        pattern1_list.append(m.start() + len(pattern1))
        
    text_file.seek(0)
    string = ""
    byte = ""
    for offset in pattern1_list:
        i += 1
        text_file.seek(offset)
        while(1):
            previous_byte = byte
            byte = text_file.read(1)
            if byte != '\x22':
                string += byte
            else:
                if previous_byte == '\x5c':
                    string += byte
                else:
                    print (offset, i, string)
                    offset_tab.append(offset)
                    string_tab.append(string)
                    string = ""
                    break
    
    output_file = open(output_file_path, 'wb+') 
    for off, strr in zip(offset_tab, string_tab):
            entry = 'string_to_translate:' + strr + '\x0d' + '\x0a'
            output_file.write(entry)

    print "Text extracted successfully!"
   
   
   
   
   
    

def text_import(text_file_path, output_file_path):
    text_file = open(text_file_path, 'rb')
    texts = text_file.read().split('string_to_translate:')
    
    text_tab = []
    for text in texts:
        text = text.rstrip('\r\n')
        text_tab.append(text)
    
    text_tab.pop(0)
    print text_tab

    pattern1_list = []
    output_file = open(output_file_path, 'rb')
    
    i = -1
    pattern1 = '\x22' + "EN" + '\x22' + ":" + '\x22'
    text = output_file.read()
    for m in re.finditer(pattern1, text):
        pattern1_list.append(m.start() + len(pattern1))    
        
    output_file.seek(0)
    string = ""
    byte = ""
    pattern2 =   "\",\"FR\":"
    #count_end = 1132
    #count_end = 318
    
    for offset in pattern1_list:
        i += 1
        #if i >= count_end:
            #print "Break at ", i, offset
            #break
        output_file.seek(offset)
        while(1):
            previous_byte = byte
            byte = output_file.read(1)
            if byte != '\x22':
                string += byte
            else:
                if previous_byte == '\x5c':
                    string += byte
                else:
                    # end_offset_tab.append()
                    #print string, '$$$$', strings_tab[i], '@@@@@'
                    text = text.replace(pattern1 + string + pattern2, pattern1 + text_tab[i] + pattern2, 1)
                    #s1 = pattern1 + string + pattern2
                    #s2 = pattern1 + text_tab[i] + pattern2
                    #print s1, s2
                    #string_tab.append(string)
                    string = ""
                    break        
        
    output_file.close()
    output_file = open(output_file_path, 'wb+')
    output_file.write(text)
    output_file.close()
    print "Text imported successfully!"    


   
   
# EXPORT TEXT
#text_file_path = 'C:\\Users\\SomeUser\\Desktop\\Localization.txt'    
#output_file_path = 'C:\\Users\\SomeUser\\Desktop\\export.txt'
#text_export(text_file_path, output_file_path)


#IMPORT TEXT
text_file_path = 'C:\\Users\\SomeUser\\Desktop\\export.txt'
output_file_path = 'C:\\Users\\SomeUser\\Desktop\\Localization.txt'    
text_import(text_file_path, output_file_path)