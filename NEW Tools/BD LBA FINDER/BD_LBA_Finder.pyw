# -*- coding: utf-8 -*-

'''
Copyright © 2020  Bartłomiej Duda
'''


# Tested on Python 3.8.0

# Ver    Date        Name               Comment
# v0.1   15.09.2020  Bartlomiej Duda    -


VERSION_NUM = "v0.1"


import os
import sys
import struct
import tkinter as tk
from tkinter import messagebox, StringVar, OptionMenu, filedialog, ttk, Text, LabelFrame, Radiobutton
from PIL import ImageTk, Image
import webbrowser
import traceback
import center_tk_window    # pip install center_tk_window
import pyperclip  # pip install pyperclip





def bd_logger(in_str):
    from datetime import datetime
    now = datetime.now()
    print(now.strftime("%d-%m-%Y %H:%M:%S") + " " + in_str)    
    

class LBA_Finder_GUI:
    def __init__(self, master):
        self.master = master
        master.title("BD LBA Finder " + VERSION_NUM)
        master.minsize(MIN_WINDOW_WIDTH, MIN_WINDOW_HEIGHT) 
        
        self.search_file_path = ""
        self.search_file_name = ""

        #main canvas
        self.canv1 = tk.Canvas(master, height=WINDOW_HEIGHT, width=WINDOW_WIDTH) 
        self.main_frame = tk.Frame(master, bg='light blue')
        self.main_frame.place(x=0, y=0, relwidth=1, relheight=1)



        self.butt1 = tk.Button(self.main_frame, text="OPEN", command=lambda: self.open_file() )
        self.butt1.place(x= 10, y= 50, width=60, height=20)   
        
        self.butt2 = tk.Button(self.main_frame, text="COPY", command=lambda: self.test1() )
        self.butt2.place(x= 60, y= 90, width=60, height=20)          
        
        self.lab1 = tk.Label(self.main_frame, text="Search file: None", anchor="w", borderwidth=1, relief="solid")
        self.lab1.place(x= 10, y= 20, width=360, height=25)   
        
        
        self.t_lab1 = tk.Label(self.main_frame, text="1)", anchor="w")
        #self.t_lab1['bg'] = self.t_lab1.master['bg']
        self.t_lab1.place(x= 10, y= 150, width=20, height=25)   
        
        self.t_lab2 = tk.Label(self.main_frame, text="2)", anchor="w")
        self.t_lab2.place(x= 10, y= 170, width=20, height=25)  
        
        self.t_lab3 = tk.Label(self.main_frame, text="3)", anchor="w")
        self.t_lab3.place(x= 10, y= 190, width=20, height=25)            
        


    def open_file(self):
        self.search_file_path = tk.filedialog.askopenfilename(initialdir = ".",title = "Select binary file")
        self.search_file_name = self.search_file_path.split("/")[-1]
        self.lab1['text'] = "Search file: " + self.search_file_name

    def test1(self):
        print("maaaaa file: " + self.search_file_path)
        print("maaaa name: " + self.search_file_name)



#default app settings
WINDOW_HEIGHT = 350
WINDOW_WIDTH = 430

MIN_WINDOW_HEIGHT = 350
MIN_WINDOW_WIDTH = 430    

#main window
root = tk.Tk()

my_gui = LBA_Finder_GUI(root)
center_tk_window.center_on_screen(root)
root.mainloop()