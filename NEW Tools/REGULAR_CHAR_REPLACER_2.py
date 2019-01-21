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
                #line.replace('Ż', 'Á')
                    #.replace('Ó', 'Ó')
                    #.replace('Ł', 'Ü')
                    #.replace('Ć', 'Ö')
                    #.replace('Ę', 'É')
                    #.replace('Ś', 'Ú')
                    #.replace('Ą', 'Ä')
                    #.replace('Ź', '¥')
                    #.replace('Ń', 'Ñ')
                    #.replace('ż', 'á')
                    #.replace('ó', 'ó')
                    #.replace('ł', 'ü')
                    #.replace('ć', 'ö')
                    #.replace('ę', 'é')
                    #.replace('ś', 'ú')
                    #.replace('ą', 'ä')
                    #.replace('ź', 'à')
                    #.replace('ń', 'ñ')
                    
                    
                    #ASCII replace
                line.replace('\xAF', '\xC1') #Ż --> 
                    .replace('\xD3', '\xD3') #Ó --> 
                    .replace('\xA3', '\xDC') #Ł --> 
                    .replace('\xC6', '\xD6') #Ć --> 
                    .replace('\xCA', '\xC9') #Ę --> 
                    .replace('\x8C', '\xDA') #Ś --> 
                    .replace('\xA5', '\xC4') #Ą --> 
                    .replace('\x8F', '\xCB') #Ź --> 
                    .replace('\xD1', '\xD1') #Ń --> 
                    
                    
                    .replace('\xBF', '\xE1') #ż --> 
                    .replace('\xF3', '\xF3') #ó --> 
                    .replace('\xB3', '\xFC') #ł --> 
                    .replace('\xE6', '\xF6') #ć --> 
                    .replace('\xEA', '\xE9') #ę --> 
                    .replace('\x9C', '\xFA') #ś --> 
                    .replace('\xB9', '\xE4') #ą --> 
                    .replace('\x9F', '\xEB') #ź --> 
                    .replace('\xF1', '\xF1') #ń -->   
                    

                    
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
tab_folders = ['c:\\Users\\User\\Desktop\\COALESCED']   
replace_chars_EXTENDED(tab_extensions, tab_folders)