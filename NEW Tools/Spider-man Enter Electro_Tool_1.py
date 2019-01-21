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


def unpack_WAD(WAD_file_path, HED_file_path, output_folder):
    HED_file = open(HED_file_path, 'rb')
    (HED_path, HED_name) = os.path.split(HED_file_path)
    (HED_short_name, temp2) = os.path.splitext(HED_name)    
    
    WAD_file = open(WAD_file_path, 'rb')
    (WAD_path, WAD_name) = os.path.split(WAD_file_path)
    (WAD_short_name, temp2) = os.path.splitext(WAD_name)   
    
    filename = ""
    file_counter = 0
    filename_arr = []
    filesize_arr = []
    
    while True:
        try:
            file_counter += 1
            back_offset = HED_file.tell()
            filename = str(HED_file.read(20)).split('\x00')[0]
            
            filename_length = len(filename)
            if (filename_length < 8):
                filename_plus_padding = 12
            elif (filename_length >= 8 and filename_length < 12):
                filename_plus_padding = 16
            else:
                filename_plus_padding = 20
                
            HED_file.seek(back_offset)
            HED_file.read(filename_plus_padding)
            file_size = struct.unpack('<i', HED_file.read(4))[0]
            
            #print file_counter, filename, file_size
            
            filename_arr.append(filename)
            filesize_arr.append(file_size)
            
        except:
            break
        
    print file_counter
    for i in range (file_counter-1):
        file_data = WAD_file.read(filesize_arr[i])
        out_path = output_folder + filename_arr[i]
        print out_path
        out_file = open(out_path, 'wb+')
        out_file.write(file_data)
        out_file.close()     
        
    HED_file.close()
    WAD_file.close()
        
        
#WAD UNPACK        
WAD_file_path = 'd:\\Spider-man 2 Enter Electro\\CD.WAD'
HED_file_path = 'd:\\Spider-man 2 Enter Electro\\CD.HED'
output_folder = 'd:\\Spider-man 2 Enter Electro\\OUT\\'
unpack_WAD( WAD_file_path, HED_file_path, output_folder)