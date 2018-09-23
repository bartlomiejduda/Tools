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



def hex_insert(file_to_insert_path, insert_into_file_path, offset, preferred_size):
    file_to_insert = open(file_to_insert_path, 'rb')
    data = file_to_insert.read()
    file_to_insert.close()
    size = len(data)
    
    if preferred_size == -1:
        preferred_size = size
    
    insert_into_file = open(insert_into_file_path, 'rb')
    
    data1 = insert_into_file.read(offset)
    skip = insert_into_file.read(preferred_size)
    data2 = insert_into_file.read() #!!!!
    insert_into_file.close()
    
    if size > preferred_size:
        data = data[0:preferred_size]
        print "\n\nWARNING! File is too big. I'm cutting file."
    elif size < preferred_size:
        data = data.ljust(preferred_size, '\x00')
        print "\n\nInserted file is smaller than preffered size. I'm filling with zeroes."
        #print data
        
    #bytess = '\x9c\x03\x00\x00\x00\x00\x00\x00'
    newfile_data = data1 + data + data2
    
    newfile = open(insert_into_file_path + '.temp', 'wb+')
    newfile.write(newfile_data)
    newfile.close()
    move(insert_into_file_path + '.temp', insert_into_file_path)    
    
    
    

#file_to_insert_path = 'd:\\Deadpool\\TransGame\\Fonts_GFX.gfx'
#insert_into_file_path = 'd:\\Deadpool\\TransGame\\Startup_int.xxx'
#offset = 6186752
#preferred_size = 547482
#hex_insert(file_to_insert_path, insert_into_file_path, offset, preferred_size)
# 6734234




file_to_insert_path = 'C:\\Users\\User\\Desktop\\CZIONKA_DIALOGOW_2\\Texture2D_415_nowy.dds'
insert_into_file_path = 'd:\\Steam\\steamapps\\common\\Deadpool\\TransGame\\CookedPC\\UI_FrontEnd_m.xxx'
offset = 11375863
preferred_size = 262308
hex_insert(file_to_insert_path, insert_into_file_path, offset, preferred_size)