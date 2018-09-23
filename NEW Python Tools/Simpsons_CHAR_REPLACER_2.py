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
                line.replace('\x7B\x01', '\xC1\x00') #Ż
                    .replace('\xD3\x00', '\xD3\x00') #Ó
                    .replace('\x41\x01', '\xDC\x00') #Ł
                    .replace('\x06\x01', '\xD6\x00') #Ć
                    .replace('\x18\x01', '\xC9\x00') #Ę
                    .replace('\x5A\x01', '\xDA\x00') #Ś
                    .replace('\x04\x01', '\xC4\x00') #Ą
                    .replace('\x79\x01', '\xA5\x00') #Ź
                    .replace('\x43\x01', '\xD1\x00') #Ń
                    .replace('\x7C\x01', '\xE1\x00') #ż
                    .replace('\xF3\x00', '\xF3\x00') #ó
                    .replace('\x42\x01', '\xFC\x00') #ł
                    .replace('\x07\x01', '\xF6\x00') #ć
                    .replace('\x19\x01', '\xE9\x00') #ę
                    .replace('\x5B\x01', '\xFA\x00') #ś
                    .replace('\x05\x01', '\xE4\x00') #ą
                    .replace('\x7A\x01', '\xE0\x00') #ź
                    .replace('\x44\x01', '\xF1\x00') #ń

                    

                    
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
#path_to_txt_folder = 'C:\\Users\\User\\Desktop\\TEST'
#replace_chars_in_regular_txt('txt', path_to_txt_folder)


##RUN EXTENDED CHAR REPLACER
tab_extensions = ['int']
tab_folders = ['d:\\The_Simpsons\\MY_MODS\\MyMod1\\']
replace_chars_EXTENDED(tab_extensions, tab_folders)