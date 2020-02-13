# -*- coding: utf-8 -*-

# Tested on Python 3.8.0
# This tool should be used with Crash Team Racing

# Ver    Date        Name
# v0.1   12.02.2020  Bartlomiej Duda


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
    print ("Starting function for extension " + extension + " and folder " + txt_folder)
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
                line.decode("utf-8").replace('Ż', 'Z')
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
                    )
            temp_file.write(line.encode("utf-8"))
            
        temp_file.close()
        txt_file.close()
        shutil.move(temp_path, txt_path)
        print ("Chars replaced in " + txt_path)
        

def replace_chars_EXTENDED(tab_extensions, tab_folders):
    for ext in tab_extensions:
        for fold in tab_folders:
            replace_chars_in_regular_txt(ext, fold)
            
            
            
##RUN EXTENDED CHAR REPLACER
tab_extensions = ['txt']
tab_folders = ['C:\\Users\\Arek\\Spolszczenia\\Crash Team Racing\\target\\NTSC\\']   
replace_chars_EXTENDED(tab_extensions, tab_folders)