# -*- coding: utf-8 -*-

# Tested on Python 3.7.3
# This tool should be used with Crash Mutant Island 2008 Java game

# Ver    Date        Name
# v1.0   27.09.2019  Bartlomiej Duda
# v1.1   28.09.2019  Bartlomiej Duda
# v1.2   29.09.2019  Bartlomiej Duda
# v1.3   30.09.2019  Bartlomiej Duda
# v1.4   01.10.2019  Bartlomiej Duda



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
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
from tkintertable import TableCanvas, TableModel, Preferences


header_dict = {}
char_dict = {}
sp_char_dict = {}
font_loaded_flag = False

def font_load(p_input_fontfile_path):
    print ("Starting Crash Java font load...")
    
    font_file = open(p_input_fontfile_path, 'rb')
    #log_file = open("out_log.txt", "wt+")
    
    
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
    #print(header_string)
    
    header_dict['Magic'] = magic
    header_dict['Font height'] = FontHeight
    header_dict['TopDec'] = TopDec
    header_dict['Space width'] = SpaceWidth
    header_dict['num_chars'] = num_chars
    header_dict['num_special_chars'] = num_special_chars
    
    
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
        
        row_char_dict = {}
        row_char_dict['Character'] = str(chr(character))
        row_char_dict['Width'] = width
        row_char_dict['Height'] = height
        row_char_dict['PositionX'] = posX
        row_char_dict['PositionY'] = posY
        row_char_dict['Position Base'] = posBase
        row_char_dict['Is_special_char'] = is_special_char
        char_dict['rec' + str(i+1)] = row_char_dict    
              
    
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
    
    #log_file.close()
    font_file.close()
    print("Ending Crash Java font load...")



def donothing():
    print("Do nothing")
    
def get_preview():
    messagebox.showinfo("Info", "No preview available")
    
def about_window(self):
        t = tk.Toplevel(self)
        t.wm_title("About")
        
        a_text = ( "Program has been created\n"
                   "by Bartłomiej Duda.\n"
                   "\n"
                   "If you want to support me,\n"
                   "you can do it here:\n"
                   "https://www.paypal.me/kolatek55\n"
                   "\n"
                   "If you want to see my other tools,\n"
                   "go to my github page:\n"
                   "https://github.com/bartlomiejduda")
        
        l = tk.Label(t, text=a_text)
        l.pack(side="top", fill="both", padx=10, pady=10)


WINDOW_HEIGHT = 500
WINDOW_WIDTH = 800


root = tk.Tk("Crash Mutant Island Font Tool", "Crash Mutant Island Font Tool")
root.winfo_toplevel().title("Crash Mutant Island Font Tool")

try:
    root.iconbitmap('favicon.ico')
except:
    print("Icon not loaded!")




canvas = tk.Canvas(root, height=WINDOW_HEIGHT, width=WINDOW_WIDTH)
canvas.pack()

header_frame = tk.Frame(root, bg='#90d1af', bd=5)
header_frame.place(relx=0.01, rely=0.01, relwidth=0.98, relheight=0.3)

h_label = tk.Label(header_frame, text="Header")
h_label.place(relwidth=0.15, height=20)

h_magic_label = tk.Label(header_frame, text="Magic:") # bg=header_frame['bg'])
h_magic_label.place(rely= 0.3, relwidth=0.15, height=20)
h_magic_text = tk.Text(header_frame, font=40)
h_magic_text.place(rely= 0.3, relx= 0.2, relwidth=0.15, height=20)
h_magic_text.configure(state='disabled', bg='light grey')

h_fontheight_label = tk.Label(header_frame, text="Font height:") 
h_fontheight_label.place(rely= 0.45, relwidth=0.15, height=20)
h_fontheight_text = tk.Text(header_frame, font=40)
h_fontheight_text.place(rely= 0.45, relx= 0.2, relwidth=0.15, height=20)

h_topdec_label = tk.Label(header_frame, text="TopDec:") 
h_topdec_label.place(rely= 0.6, relwidth=0.15, height=20)
h_topdec_entry = tk.Text(header_frame, font=40)
h_topdec_entry.place(rely= 0.6, relx= 0.2, relwidth=0.15, height=20)

h_spacewidth_label = tk.Label(header_frame, text="Space width:") 
h_spacewidth_label.place(rely= 0.3, relx=0.4, relwidth=0.25, height=20)
h_spacewidth_text = tk.Text(header_frame, font=40)
h_spacewidth_text.place(rely= 0.3, relx= 0.7, relwidth=0.15, height=20)

h_numofchars_label = tk.Label(header_frame, text="Num of chars:") 
h_numofchars_label.place(rely= 0.45, relx=0.4, relwidth=0.25, height=20)
h_numofchars_text = tk.Text(header_frame, font=40)
h_numofchars_text.place(rely= 0.45, relx= 0.7, relwidth=0.15, height=20)
h_numofchars_text.configure(state='disabled', bg='light grey')

h_numofspchars_label = tk.Label(header_frame, text="Num of special chars:") 
h_numofspchars_label.place(rely= 0.6, relx=0.4, relwidth=0.25, height=20)
h_numofspchars_text = tk.Text(header_frame, font=40)
h_numofspchars_text.place(rely= 0.6, relx= 0.7, relwidth=0.15, height=20)
h_numofspchars_text.configure(state='disabled', bg='light grey')

character_frame = tk.Frame(root, bg='light blue', bd=10)
character_frame.place(relx=0.01, rely=0.35, relwidth=0.98, relheight=0.3)

ch_label = tk.Label(character_frame, text="Character table")
ch_label.place(relwidth=0.15, height=20)

ch_button_preview = tk.Button(character_frame, text="Preview", command=lambda: get_preview())
ch_button_preview.place(relwidth=0.15, height=20, relx=0.8)






ch_frame = tk.Frame(character_frame, bg='orange')
ch_frame.place(relx=0.01, rely=0.2, relwidth=0.99, relheight=0.84)

model = TableModel()
table = TableCanvas(ch_frame, model=model)
table.show()






def open_font():
    p_input_fontfile_path = 'C:\\Users\\Adam\\Desktop\\CRASH_JAVA_FILES\\Font_nb_0'   
    font_load(p_input_fontfile_path)
    
    h_magic_text.configure(state='normal')
    h_magic_text.delete(1.0,"end-1c")
    h_magic_text.insert("end-1c", header_dict.get('Magic'))
    h_magic_text.configure(state='disabled')
    
    
    model = table.model
    model.importDict(char_dict) 

    sys.stdout.flush()
    table.redraw()
    
#open_font()


char_dict = {
        'rec1': {'Character': None, 'Width': None, 'Height': None, 'PositionX': None, 'PositionY': None, 'Position Base': None, 'Is_special_char': None}
       } 


model = table.model
model.importDict(char_dict)  


table.adjustColumnWidths()
table.autoResizeColumns()
try:
    table.resizeColumn(5, 130) #Position Base
    table.resizeColumn(6, 150) #Is_special_char
except:
    print("Couldn't resize column!")
table.redraw()

#table.showtablePrefs()





menubar = tk.Menu(root)

filemenu = tk.Menu(menubar, tearoff=0)
filemenu.add_command(label="Open", command=lambda: open_font())
filemenu.add_command(label="Save", command=donothing)
filemenu.add_command(label="Save as...", command=donothing)
filemenu.add_command(label="Close", command=donothing)
filemenu.add_separator()
filemenu.add_command(label="Exit", command=root.destroy)
menubar.add_cascade(label="File", menu=filemenu)

helpmenu = tk.Menu(menubar, tearoff=0)
helpmenu.add_command(label="About...", command=lambda: about_window(root))
menubar.add_cascade(label="Help", menu=helpmenu)

root.config(menu=menubar)


root.mainloop()