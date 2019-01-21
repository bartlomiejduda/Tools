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



def text_export(text_file_folder, output_file_path):
    data = ""
    for filename in os.listdir(text_file_folder):
        filepath = text_file_folder + filename
        #print filepath
        text_file = open(filepath, 'rb')
        
        for line in text_file:
            try:
                string = line.split('\"')[1]
                #print string
                if len(string) >= 1:
                    data += 'string_to_translate=' + string + '\x0d\x0a'
            except:
                pass
        text_file.close()
    export_file = open(output_file_path, 'wb+')
    export_file.write(data)
    export_file.close()
        
text_folder_path = 'd:\\Avernum Escape From The Pit\\Avernum Files\\Scripts\\'    
output_file_path = 'C:\\export.ini'
text_export(text_folder_path, output_file_path)