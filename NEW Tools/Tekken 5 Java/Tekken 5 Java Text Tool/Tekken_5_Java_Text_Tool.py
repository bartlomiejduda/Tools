# -*- coding: utf-8 -*-

# Tested on Python 3.8.0
# This tool should be used with Tekken 5 Java game

# Ver    Date        Name
# v0.1   05.02.2020  Bartlomiej Duda



VERSION_NUM = "v0.1"


import os
import sys
import struct
import tkinter as tk
from tkinter import messagebox, StringVar, OptionMenu, filedialog, ttk, Text, LabelFrame, Radiobutton
import webbrowser
import traceback
import stat

def read_loc(p_input_loc_filepath, p_out_filepath):
    print ("starting Crash Java sprite read...")
    loc_file = open(p_input_loc_filepath, 'rb') 
    out_file = open(p_out_filepath, 'wt+') 
    str_arr = []
    size_of_the_header = struct.unpack('>i', loc_file.read(4))[0]
    num_of_text_strings = struct.unpack('>i', loc_file.read(4))[0]
    
    loc_file.seek(loc_file.tell() + size_of_the_header) #skip header
    
    for i in range(num_of_text_strings):
        str_length = struct.unpack('>H', loc_file.read(2))[0]
        str_read = loc_file.read(str_length).decode("utf-8") 
        #print("Str: " + str(str_read))
        str_arr.append(str_read)
        
        
    #out_file.write("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
    #out_file.write("<root>\n")
    for i in range(num_of_text_strings):
        out_file.write("BD_TRANSLATE_TEXT_TAG=")
        out_file.write( str_arr[i].replace("\n", "\\n")
                       
                       )
        out_file.write("\n")
        #out_file.write("</BD_TRANSLATE_TEXT_TAG" + str(i) + ">\n")
        
    #out_file.write("</root>")
    print("Offset: " + str(loc_file.tell()))
    
    print ("Ending Crash Java sprite read...")
    
    
    
    
    
input_loc_filepath = "C:\\Users\\Arek\\Desktop\\TRAD_english.loc"
out_filepath = "C:\\Users\\Arek\\Desktop\\OUT.ini"
read_loc(input_loc_filepath, out_filepath)