# -*- coding: utf-8 -*-

# Tested on Python 3.8.5

# Ver    Date        Author
# v0.1   29.09.2020  Bartlomiej Duda

import os
import sys
import datetime


def bd_logger(in_str):
    now = datetime.datetime.now()
    print(now.strftime("%d-%m-%Y %H:%M:%S") + " " + in_str)   

def count_lines(in_file_path):
    line_count = 0
    in_file = open(in_file_path, 'rt')
    for line in in_file:
        line_count += 1
    in_file.close()
    return line_count

def count_all_files_in_folder_rec(in_folder_path, out_file_path):
    bd_logger("count_all_files_in_folder_rec start...")
    
    out_file = open(out_file_path, 'wt+')
    
    for root, subfolders, files in os.walk(in_folder_path):
        
        for file in files:
            l_count = -1
            file_path = os.path.join(root, file)
            try:
                l_count = count_lines(file_path)
            except:
                bd_logger("Couldn't count lines for file " + file)
            out_path =  root.lstrip(in_folder_path) + "\\" + file
            out_string = "Lines: " + str(l_count) + " File: " + out_path
            out_file.write(out_string + "\n")
            
    out_file.close()     
    bd_logger("count_all_files_in_folder_rec end...")
            

def main():
    p_in_folder_path = 'C:\\Users\\bartlomej.duda\\Desktop\\alair-cms\\MIGRACJA' 
    p_out_file_path = 'C:\\Users\\bartlomej.duda\\Desktop\\out.txt'
    count_all_files_in_folder_rec(p_in_folder_path, p_out_file_path)
    
    
main()