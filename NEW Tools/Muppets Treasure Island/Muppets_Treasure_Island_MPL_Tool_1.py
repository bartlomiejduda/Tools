# -*- coding: utf-8 -*-


# Ver    Date        Name
# v0.1   16.06.2019  Bartlomiej Duda


# Tool is unfinished!

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


def unpack_MPL(MPL_file_path, output_folder):
    MPL_file = open(MPL_file_path, 'rb')
    
    MPL_file.seek(44)
    size_of_the_stream_table = struct.unpack('I', MPL_file.read(4))[0]
    print size_of_the_stream_table
    
    print "Tell0_1: " + str(MPL_file.tell())
    curr_offset = MPL_file.tell()
    MPL_file.seek(curr_offset + 8 + size_of_the_stream_table + 114)
    
    print "Tell0_2: " + str(MPL_file.tell())
    sum_size = 0
    for i in range(201):
        MPL_file.read(4)
        size_of_str = struct.unpack('>h', MPL_file.read(2))[0]
        MPL_file.read(5)
        size = struct.unpack('>I', MPL_file.read(4))[0]
        MPL_file.read(2)
        sum_size += size
        filename = MPL_file.read(size_of_str-1)
        print "Size of str: " + str(size_of_str) + " Tell: " + str(MPL_file.tell())  + " Size: " + str(size)
    print "Sum_size: " + str(sum_size)
        
#MPL UNPACK        
MPL_file_path = 'C:\\Users\\Arek\\Desktop\\MEGA SYNC\MPL\\MUP_DATA.MPL'
output_folder = 'C:\\Users\\Arek\\Desktop\\MEGA SYNC\MPL\\MUP_DATA_OUT'
unpack_MPL( MPL_file_path, output_folder)