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


def BIN_unpack(bin_file_path):
    bin_file = open(bin_file_path, 'rb')
    (bin_path, bin_name) = os.path.split(bin_file_path)
    (bin_short_name, temp2) = os.path.splitext(bin_name)  
    out_folder_path = bin_path + '\\' + bin_short_name
    if not os.path.exists(out_folder_path):
        os.mkdir(out_folder_path)
        print "Created ", out_folder_path
        
    bin_file.seek(4)
    number_of_archives = struct.unpack('I', bin_file.read(4))[0]
    
    header_size_tab = []
    offset1_tab = []
    archive_name_tab = []
    
    for i in range(number_of_archives):
        header_size = struct.unpack('I', bin_file.read(4))[0]
        offset1 = struct.unpack('I', bin_file.read(4))[0]
        archive_name = bin_file.read(32).split('\x00')[0]
        header_size_tab.append(header_size)
        offset1_tab.append(offset1)
        archive_name_tab.append(archive_name)
        #print header_size, offset1, archive_name
        
        xfiles_tab = []
        files_tab = []
        
    for i in range(number_of_archives):
        bin_file.seek(offset1_tab[i] * 2048)
        bin_file.read(4) #TOC
        xfiles = struct.unpack('I', bin_file.read(4))[0]
        files = struct.unpack('I', bin_file.read(4))[0]
        bin_file.read(4) #dummy
        xfiles_tab.append(xfiles)
        files_tab.append(files)
        #print "TOC", xfiles, files
            
        
bin_file_path = 'c:\\Users\\Tomek\\Desktop\\archives_1\\MediEvil Ressurection\\gamedata.bin'
BIN_unpack(bin_file_path)    
        
        
