# -*- coding: utf-8 -*-

# Tested on Python 3.7.3

# Ver    Date        Name
# v1.0   01.06.2019  Bartlomiej Duda
# v1.1   02.06.2019  Bartlomiej Duda
# v1.2   06.06.2019  Bartlomiej Duda


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
from textwrap import wrap


h_hash_arr = []
h_name_arr = []

def Herc_hash(input_string): #calculate hash for string
  h_hash = 0
  for i in range(len(input_string)):
    h_hash += ord(input_string[i].upper()) << ((i*8)%32)
  h_hash += len(input_string)
  return h_hash

def format_hash(input_hash):
  result = str(hex(input_hash)[2:]).upper().zfill(8)
  return result

int_seq = 0
def get_seq_num():
  global int_seq
  int_seq += 1
  return int_seq

def find_name(input_hash):
  i = 0
  for h_hash in h_hash_arr:
    if h_hash == format_hash(input_hash):
      if len(h_name_arr[i]) > 2:
        return h_name_arr[i]
    i += 1
  return "\\unknown_hash_" + str(get_seq_num()) + '.BIN'
  



def unpack_FS(input_FS_file_path, output_folder_path):
    
    print("Unpacking HERCULES.FS has been started!")
    
    if not os.path.exists(output_folder_path):
      os.makedirs(output_folder_path)         
    

    Hash_file = open("herchash.txt", 'rt')
    

    for line in Hash_file: #reading hash lines from hash file
      h_hash = line.split(' ')[0]
      h_name = line.split(' ')[1]
      h_hash_arr.append(h_hash)
      h_name_arr.append(h_name)
    Hash_file.close()  
    
    
    FS_file = open(input_FS_file_path, 'rb')
    
    
    for i in range(821): #reading data from FS archive
      
      fs_hash = struct.unpack('<I', FS_file.read(4))[0]
      fs_file_offset = struct.unpack('<I', FS_file.read(4))[0]
      fs_file_length = struct.unpack('<I', FS_file.read(4))[0]
      
      fs_file_path = output_folder_path + find_name(fs_hash).lstrip('M:').lstrip('m:').rstrip('\n')
      print(str(i+1) + ") Hash: " + format_hash(fs_hash) + " File path: " + fs_file_path)
      
      return_offset = FS_file.tell()
      FS_file.seek(fs_file_offset)
      fs_data = FS_file.read(fs_file_length)
      FS_file.seek(return_offset)
      
      fs_folder_path = "\\".join(fs_file_path.split('\\')[0:-1])
      
      if not os.path.exists(fs_folder_path):
        os.makedirs(fs_folder_path)         
      
      out_file = open(fs_file_path, 'wb+')  #writing output data
      out_file.write(fs_data)
      out_file.close()
      
      
      
    #str_test = "M:\GRAFIX\CHOP\SRC1\ALIEN2\Zeus\ANIMPSX.BIN"
    #res = Herc_hash(str_test)
    #print("Res: " + format_hash(res))
    
    
    
    FS_file.close()
    print("Unpacking HERCULES.FS has been finished!")
    
    

#UNPACK FS ARCHIVE
p_input_FS_file_path = "C:\\Users\\Arek\\Desktop\\HERC_FILES\\HERCULES.FS"  
p_output_folder_path = "C:\\Users\\Arek\\Desktop\\HERC_FILES\\HERCULES_OUT"
unpack_FS(p_input_FS_file_path, p_output_folder_path)








