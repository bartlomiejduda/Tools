# -*- coding: utf-8 -*-

'''
Copyright © 2020  Bartłomiej Duda
'''


# Tested on Python 3.8.0

# Ver    Date        Name               Comment
# v0.1   15.09.2020  Bartlomiej Duda    -
# v0.2   15.09.2020  Bartlomiej Duda    -


VERSION_NUM = "v0.2"


import os
import sys
import struct
import tkinter as tk
from tkinter import messagebox, StringVar, OptionMenu, filedialog, ttk, Text, LabelFrame, Radiobutton, Scrollbar
from PIL import ImageTk, Image
import webbrowser
import traceback
import center_tk_window    # pip install center_tk_window
import pyperclip  # pip install pyperclip
from datetime import datetime



class LBA_Finder_GUI:
    def __init__(self, master):
        self.master = master
        master.title("BD LBA Finder " + VERSION_NUM)
        master.minsize(MIN_WINDOW_WIDTH, MIN_WINDOW_HEIGHT) 
        
        self.search_file_path = ""
        self.search_file_name = ""
        self.search_file_flag = 0

        #main canvas
        self.canv1 = tk.Canvas(master, height=WINDOW_HEIGHT, width=WINDOW_WIDTH) 
        self.main_frame = tk.Frame(master, bg='light blue')
        self.main_frame.place(x=0, y=0, relwidth=1, relheight=1)



        self.butt1 = tk.Button(self.main_frame, text="OPEN", command=lambda: self.open_file() )
        self.butt1.place(x= 10, y= 50, width=60, height=20)   
        
        self.butt2 = tk.Button(self.main_frame, text="SEARCH", command=lambda: self.search() )
        self.butt2.place(x= 80, y= 50, width=60, height=20)          
        
        self.lab1 = tk.Label(self.main_frame, text="Search file: None", anchor="w", borderwidth=1, relief="solid")
        self.lab1.place(x= 10, y= 20, width=360, height=25)   
        
        
        self.t_lab1 = tk.Label(self.main_frame, text="1)", anchor="nw")
        self.t_lab1['bg'] = self.t_lab1.master['bg']
        self.t_lab1.place(x= 20, y= 130, width=20, height=25)   
        
        self.t_lab2 = tk.Label(self.main_frame, text="2)", anchor="nw")
        self.t_lab2['bg'] = self.t_lab2.master['bg']
        self.t_lab2.place(x= 20, y= 150, width=20, height=25)  
        
        self.t_lab3 = tk.Label(self.main_frame, text="3)", anchor="nw")
        self.t_lab3['bg'] = self.t_lab3.master['bg']
        self.t_lab3.place(x= 20, y= 170, width=20, height=25)            
        
        self.adr_lab = tk.Label(self.main_frame, text="Address (DEC)", anchor="center")
        self.adr_lab.place(x= 40, y= 105, width=120, height=20)   
        
        self.adr_entry1 = tk.Entry(self.main_frame)
        self.adr_entry1.place(x= 40, y= 130, width=120, height=20)   
        
        self.adr_entry2 = tk.Entry(self.main_frame)
        self.adr_entry2.place(x= 40, y= 150, width=120, height=20)  
        
        self.adr_entry3 = tk.Entry(self.main_frame)
        self.adr_entry3.place(x= 40, y= 170, width=120, height=20)    
        
        
        self.adr_lab = tk.Label(self.main_frame, text="Size (DEC)", anchor="center")
        self.adr_lab.place(x= 170, y= 105, width=120, height=20)           
        
        self.size_entry1 = tk.Entry(self.main_frame)
        self.size_entry1.place(x= 170, y= 130, width=120, height=20)   
        
        self.size_entry2 = tk.Entry(self.main_frame)
        self.size_entry2.place(x= 170, y= 150, width=120, height=20)   
        
        self.size_entry3 = tk.Entry(self.main_frame)
        self.size_entry3.place(x= 170, y= 170, width=120, height=20)    
        
        
        self.log_lab = tk.Label(self.main_frame, text="Log:", anchor="w")
        self.log_lab['bg'] = self.log_lab.master['bg']
        self.log_lab.place(x= 10, y= 230, width=120, height=20)  
        

        
        self.log_text = tk.Text(self.main_frame)
        self.log_text.place(x= 10, y= 250, width=350, height=90) 
        
        self.log_scrollbar = tk.Scrollbar(self.main_frame)
        self.log_scrollbar.config(command=self.log_text.yview)
        self.log_text['yscrollcommand'] = self.log_scrollbar.set 
        self.log_scrollbar.place(x= 360, y= 250, width=15, height=90) 
        
        
        
        self.bd_logger("Program start...")


    def bd_logger(self, in_str):
        now = datetime.now()
        out_str = now.strftime("%d.%m.%Y %H:%M:%S") + " " + in_str
        self.log_text.insert(tk.END, out_str + "\n")

            
    def open_file(self):
        self.search_file_path = tk.filedialog.askopenfilename(initialdir = ".",title = "Select binary file")
        self.search_file_name = self.search_file_path.split("/")[-1]
        self.lab1['text'] = "Search file: " + self.search_file_name
        self.search_file_flag = 1

    def search(self):
        if self.search_file_flag != 1:
            tk.messagebox.showwarning("FileOpen Error #1", "No file selected!")
        
        self.search_lba(self.search_file_path)




    def search_lba(self, in_file_path):
        
        adr_arr = [12, 10764, 19468]
        size_arr = [2, 3, 4]
        
        in_file = open(in_file_path, 'rb')
        in_file_size = os.stat(in_file_path).st_size
        
        match_arr = []
        
        
        while 1:
            curr_offset = in_file.tell()
            #print(str(curr_offset) + "\r")
            #sys.stdout.flush()
            
            
            #print ("Complete: ", curr_offset, "%", end="\r")
            
            #print(str(curr_offset), end="\r") # Write the text and return
            #print(f'\r{repl: <{len(text)}}') 
            
            
            #sys.stdout.write("\rCountdown: %d" % curr_offset)
            #sys.stdout.flush()  
            
            
            self.bd_logger
            
            
            offset = struct.unpack('>I', in_file.read(4))[0]
            offset2 = struct.unpack('>I', in_file.read(4))[0]
            
            if adr_arr[0] == offset or adr_arr[0] == offset2:
                match_arr.append(curr_offset)
            else:
                in_file.seek(curr_offset+1)
        
            if curr_offset >= in_file_size - 4:
                break
        
        in_file.close()
        

#p_in_file_path = "C:\\Users\\Arek\\Desktop\\BD LBA FINDER\\DOOM.WAD"
#search_lba(p_in_file_path)

#class ThreadedTask(threading.Thread):
    #def __init__(self, queue):
        #threading.Thread.__init__(self)
        #self.queue = queue
    #def run(self):
        #time.sleep(5)  
        #self.queue.put("Task finished")


#default app settings
WINDOW_HEIGHT = 350
WINDOW_WIDTH = 380

MIN_WINDOW_HEIGHT = WINDOW_HEIGHT
MIN_WINDOW_WIDTH = WINDOW_WIDTH   

#main window
root = tk.Tk()
my_gui = LBA_Finder_GUI(root)
center_tk_window.center_on_screen(root)
root.mainloop()





