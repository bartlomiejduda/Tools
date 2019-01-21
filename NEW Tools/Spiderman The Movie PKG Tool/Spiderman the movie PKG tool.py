# -*- coding: utf-8 -*-


#Tested on Python 2.7.13
#Author of this code: Ikskoks
#It was made for XENTAX community
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
from os import listdir
from os.path import isfile, join



def PKG_unpack(pkg_file_path):
    pkg_file = open(pkg_file_path, 'rb')
    (pkg_path, pkg_name) = os.path.split(pkg_file_path)
    (pkg_short_name, temp2) = os.path.splitext(pkg_name)  
    out_folder_path = pkg_path + '\\' + pkg_short_name
    #print out_folder_path
    if not os.path.exists(out_folder_path):
        os.mkdir(out_folder_path)
        
        
    number_of_folders = struct.unpack('I', pkg_file.read(4))[0]
    number_of_files = struct.unpack('I', pkg_file.read(4))[0]
    size_of_all_files_after_unpack = struct.unpack('I', pkg_file.read(4))[0]
    #print number_of_folders, number_of_files, size_of_all_files_after_unpack
    
    arr_folder_names = []
    arr_num_fold_pointers = []
    arr_fold_pointers = []
    list_of_fold_pointers = []
    
    
    for i in range(number_of_folders):
        folder_name = pkg_file.read(64).split('\x00')[0]
        number_of_folder_pointers = struct.unpack('I', pkg_file.read(4))[0]
        #print folder_name, number_of_folder_pointers
        arr_folder_names.append(folder_name)
        arr_num_fold_pointers.append(number_of_folder_pointers)
        for i in range(number_of_folder_pointers):
            folder_pointer = struct.unpack('I', pkg_file.read(4))[0]
            #print "aaa", folder_pointer
            arr_fold_pointers.append(folder_pointer)
            
        list_of_fold_pointers.append(arr_fold_pointers)
        arr_fold_pointers = []
    
    arr_filenames = []
    arr_file_sizes = []
    arr_file_rel_offsets = []
            
    for i in range(number_of_files):
        file_name = pkg_file.read(40).split('\x00')[0]
        file_size = struct.unpack('I', pkg_file.read(4))[0]
        file_relative_offset = struct.unpack('I', pkg_file.read(4))[0]
        #print file_name, file_size, file_relative_offset
        arr_filenames.append(file_name)
        arr_file_sizes.append(file_size)
        arr_file_rel_offsets.append(file_relative_offset)
        
    end_of_filelist_offset = pkg_file.tell()
    #print end_of_filelist_offset
    
    for i in range(number_of_folders):
        out_fold_path = out_folder_path + '\\' + arr_folder_names[i]
        #print out_fold_path
        if not os.path.exists(out_fold_path):
            os.makedirs(out_fold_path)
        #print list_of_fold_pointers[i]
        
        for j in range(number_of_files):
            if j in list_of_fold_pointers[i]:
                #print arr_filenames[j]
                out_file_path = out_fold_path + arr_filenames[j]
                print out_file_path
                out_file = open(out_file_path, 'wb+')
                
                pkg_file.seek(end_of_filelist_offset + arr_file_rel_offsets[j])
                file_data = pkg_file.read(arr_file_sizes[j])
                out_file.write(file_data)
                out_file.close()
    pkg_file.close()
    print "PKG unpacked successfully"
    
def PKG_pack(pkg_folder_path):
    os.chdir(pkg_folder_path)
    file_set = glob.glob(r'*')
    file_set += glob.glob(r'*\*')
    fold = '*\\'
    fold2 = ''
    for i in range(100):
        fold2 += fold
        file_set += glob.glob(fold2 + '*')
        
    arr_dir = [] 
    arr_fil = []
    arr_fil2 = []
    num_fold = 0
    num_fil = 0
    sum_size = 0

    for dir in file_set:
        if os.path.isdir(pkg_folder_path + '\\' + dir) and dir not in arr_dir:

            if does_file_exist_in_dir(pkg_folder_path + '\\' + dir):
                arr_dir.append(dir)
                #print dir
                num_fold += 1
                
        else:
            if not os.path.isdir(pkg_folder_path + '\\' + dir) and dir not in arr_fil2:
                arr_fil2.append(dir)   
                #print dir
                num_fil += 1
                sum_size += os.stat(pkg_folder_path + '\\' + dir).st_size
                dir = dir.split('\\')[-1]
                arr_fil.append(dir)               
            
    #print num_fold, num_fil, sum_size
    
    
    out_pkg_path = pkg_folder_path  + '_new.pkg'
    print out_pkg_path
    out_pkg_file = open(out_pkg_path, 'wb+')
    
    out_pkg_file.write(struct.Struct("<l").pack(num_fold))
    out_pkg_file.write(struct.Struct("<l").pack(num_fil))
    out_pkg_file.write(struct.Struct("<l").pack(sum_size))    
    
    arr_id_numb = []
    id_count = 0
    for i in range(num_fold):
        name = (arr_dir[i] + '\x00').ljust(64,'\xEE')
        f_path = pkg_folder_path + '\\' + arr_dir[i]
        os.chdir(f_path)
        file_set = glob.glob(r'*') 
        
        #print "######"
        for file in file_set:
            try:
                #print file
                ind = arr_fil.index(file)
                arr_id_numb.append(ind)
                id_count += 1
            except:
                pass
                
        #print arr_id_numb
        out_pkg_file.write(name)
        out_pkg_file.write(struct.Struct("<l").pack(id_count))
        for id_numb in arr_id_numb:
            out_pkg_file.write(struct.Struct("<l").pack(id_numb))
        
        arr_id_numb = []
    
    rel_offset = 0    
    for i in range(num_fil):
        f_name = (arr_fil[i] + '\x00').ljust(40,'\xEE')
        f_path = pkg_folder_path + '\\' + arr_fil2[i]
        f_size = os.stat(f_path).st_size
        
        #print f_name, f_size, rel_offset
        
        out_pkg_file.write(f_name)
        out_pkg_file.write(struct.Struct("<l").pack(f_size))
        out_pkg_file.write(struct.Struct("<l").pack(rel_offset))
        rel_offset += f_size
        
    for i in range(num_fil):
        f_path = pkg_folder_path + '\\' + arr_fil2[i]
        some_file = open(f_path, 'rb')
        f_data = some_file.read()
        out_pkg_file.write(f_data)
        some_file.close()
        
    print "PKG packed successfully."
    #print len(arr_fil2)
    #print num_fil
        

        
def does_file_exist_in_dir(path):
    return any(isfile(join(path, i)) for i in listdir(path))


def extract_text(game_folder_path, white_list_file_path):
    #print "Starting function for extension " + extension + " and folder " + txt_folder
    
    arr_white_list = []
    if len(white_list_file_path) > 0:
        b_file = open( white_list_file_path, 'rb') 
        for line in b_file:
            arr_white_list.append(line.replace('\r', '').replace('\n', ''))
        b_file.close()
    
    
    os.chdir(game_folder_path)
    extension = "SX"
    file_set = glob.glob(r'*.' + extension)
    file_set += glob.glob(r'*\*.' + extension)
    fold = '*\\'
    fold2 = ''
    for i in range(100):
        fold2 += fold
        file_set += glob.glob(fold2 + '*.' + extension)
    for file in file_set:
        f_path = os.path.abspath(file)
        
        f_file = open(f_path, 'rb')    
        
        line_count = 0
        for line in f_file:
            line_count += 1
            line = line.split('\n')[0]
            if line.startswith("\"") and line.endswith("\"") and line in arr_white_list:
                print line.split('\n')[0], line_count, f_file.name
            
        print arr_white_list



#pkg_file_path = 'C:\\Users\\User\\Desktop\\SPIDERMAN THE MOVIE\\BRIDGE_A.pkg'
#PKG_unpack(pkg_file_path)

pkg_folder_path = 'c:\\Users\\User\\Desktop\\SPIDERMAN THE MOVIE\\ACME_E\\'
PKG_pack(pkg_folder_path)


#game_folder_path = 'C:\\Users\\User\\Desktop\\SPIDERMAN THE MOVIE\\ACME_E'
#white_list_file_path = 'C:\\Users\\User\\Desktop\\SPIDERMAN THE MOVIE\\WHITE_LIST.txt'
#extract_text(game_folder_path, white_list_file_path)