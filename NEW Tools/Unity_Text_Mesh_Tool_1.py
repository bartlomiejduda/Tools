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



def text_export(input_folder_path, output_file_path):
    files_102_tab = []
    strings_tab = []
    reimport_tab = []
    
    extension = '102'
    os.chdir(input_folder_path)
    file_set = glob.glob(r'*.' + extension)
    file_set += glob.glob(r'*\*.' + extension)
    fold = '*\\'
    fold2 = ''
    for i in range(100):
        fold2 += fold
        file_set += glob.glob(fold2 + '*.' + extension)
    for file in file_set:    
        bin_path = os.path.abspath(file)
        files_102_tab.append(bin_path)
    files_102_tab = set(files_102_tab) #distinct names
    
    for file_102 in files_102_tab:
        print file_102 
        bin_file = open(file_102, 'rb')
        bin_file.read(8)
        string_length = struct.unpack('I', bin_file.read(4))[0]
        string = bin_file.read(string_length)
        #print string
        bin_file.close()
        
        strings_tab.append(string)
        reimport_tab.append(file_102)
        
    output_file = open(output_file_path, 'wb+')
    reimport_data_path = output_file_path + '_reimport'
    reimport_data_file = open(reimport_data_path, 'wb+')
    
    for strr in strings_tab:
        output_file.write('string_to_translate=' + strr + '\x0D' + '\x0A')
    for reim in reimport_tab:
        reimport_data_file.write(reim + '\x0D' + '\x0A')
    
    output_file.close()
    reimport_data_file.close()
    print "Program finished!"
    
    
input_folder_path = 'C:\\Steam\\steamapps\\common\\That Dragon, Cancer\\TDC_Data\\Unity_Assets_Files\\'   #put here folder with ".102" files exported by UnityEx
output_file_path = 'C:\\Users\\User\\Desktop\\out.ini'  #put here output ini file
text_export(input_folder_path, output_file_path)