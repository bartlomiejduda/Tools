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


def MST_unpack(mst_file_path):
    mst_file = open(mst_file_path, 'rb')
    (mst_path, mst_name) = os.path.split(mst_file_path)
    (mst_short_name, temp2) = os.path.splitext(mst_name)  
    out_folder_path = mst_path + '\\' + mst_short_name
    if not os.path.exists(out_folder_path):
        os.mkdir(out_folder_path)
    
    mst_file.seek(12)
    number_of_files = struct.unpack('I', mst_file.read(4))[0]
    print number_of_files
    
    mst_file.seek(108)
    for i in range(number_of_files):
        filename = mst_file.read(16).split('\x00')[0]
        offset = struct.unpack('I', mst_file.read(4))[0]
        size = struct.unpack('I', mst_file.read(4))[0]
        something1 = struct.unpack('B', mst_file.read(1))[0]
        something2 = struct.unpack('B', mst_file.read(1))[0]
        something3 = struct.unpack('B', mst_file.read(1))[0]
        something4 = struct.unpack('B', mst_file.read(1))[0]
        ret_offset = mst_file.tell()
        #print filename, offset, size, ' ----> ', something1, something2, something3, something4
        
        mst_file.seek(offset)
        out_file_data = mst_file.read(size)
        out_file_path = out_folder_path + '\\' + filename
        out_file = open(out_file_path, 'wb+')
        out_file.write(out_file_data)
        
        
        mst_file.seek(ret_offset)
        print "File ", filename, " extracted to ",  out_file_path
    

def MST_unpack_all(folder_with_archives): 
    extension = 'mst'
    os.chdir(folder_with_archives)
    file_set = glob.glob(r'*.' + extension)
    for file in file_set:
        mst_path = os.path.abspath(file)    
        MST_unpack(mst_path)


#mst_file_path = 'C:\\Users\\Radek\\Desktop\\archives_1\\Scooby Doo na PSP\\SDBOOTUP - Kopia.MST'
#MST_unpack(mst_file_path)


folder_with_archives = 'C:\\Users\\Radek\\Desktop\\archives_1\\Scooby Doo na PSP'
MST_unpack_all(folder_with_archives)