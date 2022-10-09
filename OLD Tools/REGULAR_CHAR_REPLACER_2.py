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


def replace_chars_in_regular_txt(extension, txt_folder):
    print "Starting function for extension " + extension + " and folder " + txt_folder
    os.chdir(txt_folder)
    file_set = glob.glob(r'*.' + extension)
    file_set += glob.glob(r'*\*.' + extension)
    fold = '*\\'
    fold2 = ''
    for i in range(100):
        fold2 += fold
        file_set += glob.glob(fold2 + '*.' + extension)
    for file in file_set:
        txt_path = os.path.abspath(file)
        
        temp_path = os.path.dirname(txt_path)
        temp_filename = txt_path.split('\\')[-1].split('.')[0]
        temp_path += '\\' + temp_filename + '_temp.txt'
        
        temp_file = open(temp_path, 'wb+')
        txt_file = open(txt_path, 'rb')
        
        for line in txt_file:
            line = (
                line.replace('Ż', 'Z')
                    .replace('Ó', 'O')
                    .replace('Ł', 'L')
                    .replace('Ć', 'C')
                    .replace('Ę', 'E')
                    .replace('Ś', 'S')
                    .replace('Ą', 'A')
                    .replace('Ź', 'Z')
                    .replace('Ń', 'N')
                    .replace('ż', 'z')
                    .replace('ó', 'o')
                    .replace('ł', 'l')
                    .replace('ć', 'c')
                    .replace('ę', 'e')
                    .replace('ś', 's')
                    .replace('ą', 'a')
                    .replace('ź', 'z')
                    .replace('ń', 'n')
                    
                    
                    .replace('\xAF', '\x5A') #Ż --> Z
                    .replace('\xD3', '\x4F') #Ó --> O
                    .replace('\xA3', '\x4C') #Ł --> L
                    .replace('\xC6', '\x43') #Ć --> C
                    .replace('\xCA', '\x45') #Ę --> E
                    .replace('\x8C', '\x53') #Ś --> S
                    .replace('\xA5', '\x41') #Ą --> A
                    .replace('\x8F', '\x5A') #Ź --> Z
                    .replace('\xD1', '\x4E') #Ń --> N
                    .replace('\xBF', '\x7A') #ż --> z
                    .replace('\xF3', '\x6F') #ó --> o
                    .replace('\xB3', '\x6C') #ł --> l
                    .replace('\xE6', '\x63') #ć --> c
                    .replace('\xEA', '\x65') #ę --> e
                    .replace('\x9C', '\x73') #ś --> s
                    .replace('\xB9', '\x61') #ą --> a
                    .replace('\x9F', '\x7A') #ź --> z
                    .replace('\xF1', '\x6E') #ń --> n                
                    )
            temp_file.write(line)
            
        temp_file.close()
        txt_file.close()
        shutil.move(temp_path, txt_path)
        print "Chars replaced in " + txt_path
        

def replace_chars_EXTENDED(tab_extensions, tab_folders):
    for ext in tab_extensions:
        for fold in tab_folders:
            replace_chars_in_regular_txt(ext, fold)
            
            
            
##RUN CHAR REPLACER
#path_to_txt_folder = 'C:\\Users\\Grzesiek\\Desktop\\TEST'
#replace_chars_in_regular_txt('txt', path_to_txt_folder)


##RUN EXTENDED CHAR REPLACER
tab_extensions = ['txt', 'ini', 'int']
tab_folders = ['C:\\Users\\Grzesiek\\Desktop\\TEST', 'C:\\Users\\Grzesiek\\Desktop\\TEST2']
replace_chars_EXTENDED(tab_extensions, tab_folders)