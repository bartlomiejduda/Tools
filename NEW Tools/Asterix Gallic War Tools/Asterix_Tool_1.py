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



def unpack_DAT(DAT_file_path, output_folder):
    DAT_file = open(DAT_file_path, 'rb')
    (DAT_path, DAT_name) = os.path.split(DAT_file_path)
    (DAT_short_name, temp2) = os.path.splitext(DAT_name)     
    
    j = 0
    number_of_files = 3258
    for i in range(number_of_files):
        #print i
        file_size = struct.unpack('<i', DAT_file.read(4))[0]
        file_data = DAT_file.read(file_size)
        #print DAT_file.tell(), file_size
        #DAT_file.read(4)
        
        file_name = "File" + str(j+1) + '.VAG'
        j += 1
        VAG_path = output_folder + '\\' + file_name
        print VAG_path
        VAG_file = open(VAG_path, 'wb+')
        VAG_file.write(file_data)
        VAG_file.close()
 


#DAT UNPACK        
DAT_file_path = 'C:\\Users\\User\\Desktop\\ASTERIX\\ASTERIX.DAT'
output_folder = 'C:\\Users\\User\\Desktop\\ASTERIX\\OUT'
unpack_DAT( DAT_file_path,  output_folder)