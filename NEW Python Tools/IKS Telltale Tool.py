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


def delete_files(path, pattern):
    for f in glob.iglob(os.path.join(path, pattern)):
        try:
            os.remove(f)
            
        except OSError as exc:
            print exc
    print "Done!"

path = 'd:\\Steam\\steamapps\\common\\JurassicPark\\Pack\\TTG_TOOLS\\output'
pattern = '*french*'
delete_files(path, pattern)
pattern = '*german*'
delete_files(path, pattern)


def txt_to_lng(txt_path):
    txt_file = open(txt_path, 'rt')
    arr_key = []
    arr_val = []
    
    for line in txt_file:

        if (line[0].isdigit() and line[1] == ')') or (line[0].isdigit() and line[1].isdigit() and line[2] == ')') or (line[0].isdigit() and line[1].isdigit() and line[2].isdigit() and line[3] == ')'):
            arr_key.append(line)
        else:
            arr_val.append(line)
            
    txt_file.close()
    
    key_num = len(arr_key)
    lng_path = txt_path.replace('txt', 'lng')
    lng_file = open(lng_path, 'wt+')
    for i in range(key_num):
        string = arr_key[i] + "=" 
        string += arr_val[i]
        lng_file.write(string)
        
        
        
        
#txt_path = 'd:\\Steam\\steamapps\\common\\JurassicPark\\Pack\\TTG_TOOLS\\output\\env_junglenedrysclearing_exploreclearing_english.txt'
#txt_to_lng(txt_path)
        


def txt_to_lng_extended(input_folder):
    for filename in os.listdir(input_folder):
        filepath = os.path.abspath(os.path.join(input_folder, filename))
        txt_to_lng(filepath)
        print "TXT file " + filepath + " converted to LNG file."
        
        
input_folder = 'd:\\Steam\\steamapps\\common\\JurassicPark\\Pack\\TTG_TOOLS\\output\\'
txt_to_lng_extended(input_folder)



