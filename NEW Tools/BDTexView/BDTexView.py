# -*- coding: utf-8 -*-

# Tested on Python 3.8.1

# Ver    Date        Name
# v1.0   08.01.2020  Bartlomiej Duda


VERSION_NUM = "v1.0"


import os
import sys
import struct
import tkinter as tk
from tkinter import messagebox, StringVar, OptionMenu, filedialog, ttk, Text, LabelFrame, Radiobutton
import webbrowser
import traceback


def open_manual():
    filename = "bdtexview_manual.html"
    webbrowser.open('file://' + os.path.realpath(filename))
    
def callback(url):
    webbrowser.open_new(url)


def about_window(self):
        t = tk.Toplevel(self)
        t.wm_title("About")
        
        a_text = ( "BDTexView\n"
                   "Version: " + VERSION_NUM + "\n"
                   "\n"
                   "Program has been created\n"
                   "by Bartłomiej Duda.\n"
                   "\n"
                   "If you want to support me,\n"
                   "you can do it here:" )        
        a_text2 = ( "https://www.paypal.me/kolatek55" )
        a_text3 = ( "\n"
                    "If you want to see my other tools,\n"
                    "go to my github page:" )
        a_text4 = ( "https://github.com/bartlomiejduda" )
        
        l = tk.Label(t, text=a_text)
        l.pack(side="top", fill="both", padx=10)
        l2 = tk.Label(t, text=a_text2, fg="blue", cursor="hand2")
        l2.bind("<Button-1>", lambda e: callback(a_text2))
        l2.pack(side="top", anchor='n')
        l3 = tk.Label(t, text=a_text3)
        l3.pack(side="top", fill="both", padx=10)        
        l4 = tk.Label(t, text=a_text4, fg="blue", cursor="hand2")
        l4.bind("<Button-1>", lambda e: callback(a_text4))
        l4.pack(side="top", anchor='n')    



WINDOW_HEIGHT = 230
WINDOW_WIDTH = 500


root = tk.Tk("BDTexView", "BDTexView")
root.winfo_toplevel().title("BDTexView " + VERSION_NUM)

try:
    root.iconbitmap('bdtexview_icon.ico')
except:
    print("Icon not loaded!")


canvas = tk.Canvas(root, height=WINDOW_HEIGHT, width=WINDOW_WIDTH)
canvas.pack()

main_frame = tk.Frame(root, bg='light blue', bd=5)
main_frame.place(relx=0.01, rely=0.01, relwidth=0.98, relheight=0.98)



txt_pack_label = tk.Label(main_frame, text="Graphic filepath")
txt_pack_label.place(relx=0.01, rely=0.1, relwidth=0.2, height=20)
txt_pack_text = tk.Text(main_frame, font=("Arial", 10), wrap='none')
txt_pack_text.place(relx= 0.01, rely= 0.2, relwidth=0.65, height=20)
txt_pack_button = tk.Button(main_frame, text="Browse", command=lambda: b_browse(1))
txt_pack_button.place(relx= 0.69, rely= 0.2, relwidth=0.2, height=20)



class Path_Exception(Exception):
    pass


mode_frame = LabelFrame(main_frame, text="Pixel formats", padx=5, pady=5)
mode_frame['bg'] = mode_frame.master['bg']
mode_frame.place(relx= 0.7, rely= 0.4, relwidth=0.28, relheight=0.34)
v = StringVar()
v.set("M1")
radio_b_1 = Radiobutton(mode_frame, text="16x4 = 48+16", variable=v, value="P1", bg="light blue", command=lambda: change_mode("M1")).pack()
radio_b_2 = Radiobutton(mode_frame, text="16x3 = 48", variable=v, value="P2", bg="light blue", command=lambda: change_mode("M2")).pack()







menubar = tk.Menu(root)

filemenu = tk.Menu(menubar, tearoff=0)
filemenu.add_command(label="Exit", command=root.destroy)
menubar.add_cascade(label="File", menu=filemenu)

helpmenu = tk.Menu(menubar, tearoff=0)
helpmenu.add_command(label="Manual", command=lambda: open_manual())
helpmenu.add_command(label="About...", command=lambda: about_window(root))
menubar.add_cascade(label="Help", menu=helpmenu)
root.config(menu=menubar)

root.mainloop()