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
from tempfile import mkstemp
from shutil import move
from os import remove, close
import StringIO



def unpack_spr( path_to_spr ): 
       spr_file = open(path_to_spr, 'rb')
       (bmp_path, bmp_name) = os.path.split(path_to_spr)
       (bmp_short_name, temp2) = os.path.splitext(bmp_name) 
       
       spr_file.seek(72)
       j = 1
       
       bmp_path2 = bmp_path + '\\' + bmp_short_name + '\\'
       if not os.path.exists(bmp_path2):
              os.mkdir(bmp_path2)       
       
       
       while True:
             
              width = struct.unpack('I', spr_file.read(4))[0] 
              height = struct.unpack('I', spr_file.read(4))[0]    
              size = width * height * 2
              #image_data = spr_file.read(size)
              try:
                     image_data_io = StringIO.StringIO(spr_file.read(size))
              except:
                     break              
              
              bmp_name = "Image" + str(j) + '.bmp'
              bmp_new_path = bmp_path2 + '\\' + bmp_name
              j += 1
              print bmp_new_path
              
              
              
              bmp_file = open(bmp_new_path, 'wb+')
              #                        size                  unused               pixel arr off       size of dib hed
              header = '\x42\x4d' + '\x0a\x29\x00\x00' + '\x00\x00\x00\x00' + '\x8a\x00\x00\x00' + '\x7c\x00\x00\x00'
              bmp_file.write(header)
              
              bmp_file.write(struct.Struct("<l").pack(width))
              bmp_file.write(struct.Struct("<l").pack(height))
              
              #            color plan   b per pix     ???                  size of raw 
              header2 = '\x01\x00' + '\x10\x00' + '\x03\x00\x00\x00' + '\x80\x28\x00\x00' + '\xc4\x0e\x00\x00' '\xf1\x00\x00\x00' + '\x00\x00\x00\x00' + '\x00\x00\x00\x00'
              bmp_file.write(header2)     
              bitmask565 = '\x00\xF8\x00\x00\xE0\x07\x00\x00\x1F\x00\x00\x00'
              bmp_file.write(bitmask565) 
              header4 = '\x00\x00\x00\x00\x42\x47\x52\x73\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00';
              bmp_file.write(header4) 
       
              
              #num_rows = size / height
              row_size = size / height
              data_arr = []
              
              for i in range(height):
                     data_row = image_data_io.read(row_size)
                     data_arr .append(data_row)
                     
              data_arr.reverse()
                     
              for i in range(height):
                     bmp_file.write(data_arr[i])       
              
              
              bmp_file.close()
              
              #bmp_file.write(image_data)       
              
       print " End...."
       
       


path_to_spr = 'C:\\Users\\Tomek\\Desktop\\World.spr'
unpack_spr( path_to_spr )


