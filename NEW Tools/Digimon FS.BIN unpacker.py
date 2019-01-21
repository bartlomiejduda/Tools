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






def extract_BIN(input_bin_file_path, output_folder):
    print "Start processing!"

    bin_file = open(input_bin_file_path, 'rb')
    
    size_str = ''
    f_path = ''
    break_flag = 0
    
    size_arr = []
    f_path_arr = []
    counter = 0
    
    while 1:
        while 1: #checking for end of file list
            back_offset = bin_file.tell()
            bin_file.read(2)
            byte = bin_file.read(1)
            if byte != '\x00':
                bin_file.seek(back_offset)
                break
            else:
                break_flag = 1
                break
        if break_flag == 1:
            break
        
        while 1:
            byte = bin_file.read(1)
            if byte == '\x2C':
                break
            size_str += struct.unpack('c', byte)[0]
        size_int = int(size_str)
        size_int = size_int * 23 #is it alright?
        size_arr.append(size_int)
        #print size_int
        size_str = ''
        
        while 1:
            byte = bin_file.read(1)
            if byte == '\x0D' or byte == '\x0A':
                break
            f_path += struct.unpack('c', byte)[0]
        f_path_arr.append(f_path)
        #print f_path
        f_path = ''
         
    
    #bin_file.seek(55296)
    
    for i in range(len(f_path_arr)):
        size = size_arr[i]
        path = f_path_arr[i]
        out_path = output_folder + '\\' + path
        
        counter += 1
        print "File ", counter, ": ", size, out_path
        f_data = bin_file.read(size)
        
        
        if not os.path.exists(os.path.dirname(out_path)):
            try:
                os.makedirs(os.path.dirname(out_path))
            except OSError as exc: 
                if exc.errno != errno.EEXIST:
                    raise        
        
        
        out_file = open(out_path, 'wb+')
        out_file.write(f_data)
        out_file.close()
        
    
    
    bin_file.close()
    print "END of processing"
    
            
input_bin_file_path = 'e:\\DIGIMON_GAME\\FS.BIN'   #put here input FS.BIN file path
output_folder = 'e:\\DIGIMON_GAME\\OUT'  #put here output folder
extract_BIN(input_bin_file_path, output_folder)


