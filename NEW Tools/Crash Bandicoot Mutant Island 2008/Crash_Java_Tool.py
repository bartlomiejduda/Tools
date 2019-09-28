# -*- coding: utf-8 -*-

# Tested on Python 3.7.3
# This tool should be used with Crash Mutant Island 2008 Java game

# Ver    Date        Name
# v1.0   27.09.2019  Bartlomiej Duda
# v1.1   28.09.2019  Bartlomiej Duda



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



def font_load(p_input_fontfile_path):
    print ("Starting Crash Java font load...")

    font_file = open(p_input_fontfile_path, 'rb')
    log_file = open("out_log.txt", "wt+")
    
    
    #read header
    magic = struct.unpack('3s', font_file.read(3))[0]
    FontHeight = struct.unpack('>B', font_file.read(1))[0]
    TopDec = struct.unpack('>B', font_file.read(1))[0]
    SpaceWidth = struct.unpack('>B', font_file.read(1))[0]
    num_chars = struct.unpack('>H', font_file.read(2))[0]
    num_special_chars = struct.unpack('>H', font_file.read(2))[0]
    header_string = ( "magic: " + str(magic) + " FontHeight: " + str(FontHeight) +
                      " TopDec: " + str(TopDec) + " SpaceWidth: " + str(SpaceWidth) +
                      " num_chars: " + str(num_chars) + " num_sp_chars: " + str(num_special_chars) )
    print(header_string)
    
  
    for i in range(num_chars): #read character table
        current_offset = font_file.tell()
        character = struct.unpack('>H', font_file.read(2))[0]
        width = struct.unpack('>B', font_file.read(1))[0]
        height = struct.unpack('>B', font_file.read(1))[0]
        posX = struct.unpack('>B', font_file.read(1))[0]
        posY = struct.unpack('>B', font_file.read(1))[0]
        posBase = struct.unpack('>B', font_file.read(1))[0]
        is_special_char = -1
        log_string = (str(i+1) + ") char: " + str(chr(character)) + " width: " + str(width) + 
              " height: " + str(height) + " posX: " + str(posX) + " posY: " + str(posY) + " posBase: " + str(posBase) + 
              " is_special: " + str(is_special_char) + " curr_offset: " + str(current_offset) )
        #print(log_string)
        #log_file.write(log_string + '\n')
    
    n = 0
    for j in range(num_special_chars): #read special character table
        current_offset = font_file.tell()
        special_character = struct.unpack('>H', font_file.read(2))[0]
        width = struct.unpack('>B', font_file.read(1))[0]
        height = struct.unpack('>B', font_file.read(1))[0]  
        posBase = struct.unpack('>B', font_file.read(1))[0]
        is_special_char = n
        loop_string_all = ""
        for i in range(2):
            index = struct.unpack('>H', font_file.read(2))[0]
            XOffset = struct.unpack('>B', font_file.read(1))[0]
            YOffset = struct.unpack('>B', font_file.read(1))[0]
            n += 1
            loop_string = ( "index: " + str(index) + " XOffset: " + str(XOffset) + " YOffset: " + str(YOffset) + '\n')
            loop_string_all += loop_string
        
        log_string = (str(j+1) + ") sp_char: " + str(chr(special_character)) + " width: " + str(width) + 
              " height: " + str(height) + " posBase: " + str(posBase) + 
              " is_special: " + str(is_special_char) + " curr_offset: " + str(current_offset) + '\n' + loop_string_all)  
        #print(log_string)
    
    log_file.close()
    font_file.close()
    print("Ending Crash Java font load...")

#FONT LOAD
p_input_fontfile_path = 'C:\\Users\\Adam\\Desktop\\CRASH_JAVA_FILES\\Font_nb_0'   
font_load(p_input_fontfile_path)

