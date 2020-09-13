# -*- coding: utf-8 -*-

'''
Copyright © 2020  Bartłomiej Duda
'''


# Tested on Python 3.8.0

# Ver    Date        Name               Comment
# v0.1   13.09.2020  Bartlomiej Duda    -


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

def main():
    
    #default app settings
    WINDOW_HEIGHT = 350
    WINDOW_WIDTH = 430
    
    MIN_WINDOW_HEIGHT = 350
    MIN_WINDOW_WIDTH = 430    
    
    #main window
    root = tk.Tk("BD HEX DEC CONVERTER", "BD HEX DEC CONVERTER")
    root.minsize(MIN_WINDOW_WIDTH, MIN_WINDOW_HEIGHT) 
    root.winfo_toplevel().title("BD HEX DEC CONVERTER " + VERSION_NUM)
    
    try:
        root.iconbitmap('icon_bd.ico')
    except:
        bd_logger("Icon not loaded!")
    
    

    
    #main canvas
    canvas = tk.Canvas(root, height=WINDOW_HEIGHT, width=WINDOW_WIDTH) 
    main_frame = tk.Frame(root, bg='light blue')
    main_frame.place(x=0, y=0, relwidth=1, relheight=1)
    
    
    
    #INPUT
    i_label = tk.Label(main_frame, text="Input DEC/HEX" , anchor="w")
    i_label['bg'] = i_label.master['bg']
    i_label.place(x= 20, y= 20, width=120, height=20)      
    
    i_entry = tk.Entry(main_frame)
    i_entry.place(x= 20, y=40, width=120, height=20)     
    
    i_labframe1 = LabelFrame(main_frame, text="Mode select", padx=5, pady=5)
    i_labframe1['bg'] = i_labframe1.master['bg']
    i_labframe1.place(x=250, y=20, width=135, height=110)     
    
    
    mode = StringVar()
    mode.set("M1")
    radio_b_1 = Radiobutton(i_labframe1, text="DEC --> HEX", variable=mode, value="M1", bg="light blue", command=lambda: change_mode(mode, "M1"))
    radio_b_1.place(relx=0, x=5, y= 10, width=95, height=20) 
    radio_b_2 = Radiobutton(i_labframe1, text="HEX --> DEC", variable=mode, value="M2", bg="light blue", command=lambda: change_mode(mode, "M2"))
    radio_b_2.place(relx=0, x=5, y= 40, width=95, height=20)     
    
    
    
    #OUTPUT 1
    o_label = tk.Label(main_frame, text="Output value" , anchor="w")
    o_label['bg'] = o_label.master['bg']
    o_label.place(x= 20, y= 170, width=120, height=20)      
    
    o_entry = tk.Entry(main_frame)
    o_entry.place(x= 20, y=190, width=170, height=20)   
    o_entry['readonlybackground'] = "white"
    o_entry['state'] = 'readonly'
    
    

    
    o_butt_copy1 = tk.Button(main_frame, text="COPY", command=lambda: copy_value(o_entry) )
    o_butt_copy1.place(x= 200, y= 190, width=60, height=20)   
    

    
    
    #OUTPUT 2
    o_label2 = tk.Label(main_frame, text="Output value (BE & Padded)" , anchor="w")
    o_label2['bg'] = o_label2.master['bg']
    o_label2.place(x= 20, y= 230, width=170, height=20)      
    
    o_entry2 = tk.Entry(main_frame)
    o_entry2.place(x= 20, y=250, width=170, height=20)  
    o_entry2['readonlybackground'] = "white" 
    o_entry2['state'] = 'readonly'    
    
    o_butt_copy2 = tk.Button(main_frame, text="COPY", command=lambda: copy_value(o_entry2) )
    o_butt_copy2.place(x= 200, y= 250, width=60, height=20)   
    
    check2_var = tk.IntVar()
    o_check2 = tk.Checkbutton(main_frame, text="Spaces?", variable=check2_var, command=lambda: make_spaces(check2_var, o_entry2) )
    o_check2['bg'] = o_check2.master['bg']
    o_check2.place(x= 270, y= 250, width=60, height=20)       
    
    
    #OUTPUT 3
    o_label3 = tk.Label(main_frame, text="Output value (LE & Padded)" , anchor="w")
    o_label3['bg'] = o_label3.master['bg']
    o_label3.place(x= 20, y= 290, width=170, height=20)      
    
    o_entry3 = tk.Entry(main_frame)
    o_entry3.place(x= 20, y=310, width=170, height=20) 
    o_entry3['readonlybackground'] = "white"
    o_entry3['state'] = 'readonly'    
    
    o_butt_copy3 = tk.Button(main_frame, text="COPY", command=lambda: copy_value(o_entry3) )
    o_butt_copy3.place(x= 200, y= 310, width=60, height=20)   
    
    check3_var = tk.IntVar()
    o_check3 = tk.Checkbutton(main_frame, text="Spaces?", variable=check3_var, command=lambda: make_spaces(check3_var, o_entry3) )
    o_check3['bg'] = o_check3.master['bg']
    o_check3.place(x= 270, y= 310, width=60, height=20)        
    
    
    
    i_butt1 = tk.Button(main_frame, text="CONVERT", command=lambda: convert_value(mode, i_entry, o_entry, o_entry2, o_entry3, check2_var, check3_var) )
    i_butt1.place(x= 150, y= 40, width=80, height=20)      
    
    
    
    
    center_tk_window.center_on_screen(root)
    root.mainloop()





def change_mode(var, val):
    var.set(val)
    
def copy_value(o_entry): 
    o_entry['state'] = 'normal'    
    o_entry_str = o_entry.get()
    pyperclip.copy(o_entry_str)
    pyperclip.paste()
    o_entry['state'] = 'readonly' 
    
def make_spaces(ch_var, o_entry):
    o_entry['state'] = 'normal'   
    i_ch_var = ch_var.get()
    
    str_o_entry = o_entry.get()
    
    if len(str_o_entry) < 1:
        tk.messagebox.showwarning("MakeSpaces Error #1", "Field is empty!")
        ch_var.set(0)
        return
    
    str_o_entry = str_o_entry.replace(" ", "")
    
    n = 2
    o_entry_arr = [str_o_entry[i:i+n] for i in range(0, len(str_o_entry), n)]
    len_o_entry_arr = len(o_entry_arr)
    
    spaces_out_val = ""
    if i_ch_var == 0:
        for i in range(len_o_entry_arr):
            spaces_out_val += o_entry_arr[i]     
    elif i_ch_var == 1:
        for i in range(len_o_entry_arr):
            spaces_out_val += o_entry_arr[i] + " "
    

    o_entry.delete(0,tk.END)
    o_entry.insert(0,spaces_out_val)      
    o_entry['state'] = 'readonly'   
    
    
def convert_value(mode, i_entry, o_entry, o_entry2, o_entry3, check2_var, check3_var):
    o_entry['state'] = 'normal'   
    o_entry2['state'] = 'normal'   
    o_entry3['state'] = 'normal'   
    
    check2_var.set(0)
    check3_var.set(0)
    
    str_mode = mode.get()
    
    if str_mode == "M1": # DEC --> HEX
        in_val = i_entry.get()
        
        
        try:
            i_in_val = int(in_val)
        except:
            tk.messagebox.showwarning("Conversion Error #1", "This is not a valid integer value to convert!")
            return
        
        # OUTPUT 1
        h_out_val = str(hex(i_in_val))
        h_out_val = h_out_val[0:2] + h_out_val[2:].upper()
        o_entry.delete(0,tk.END)
        o_entry.insert(0,h_out_val)   
        
        # OUTPUT 2
        h_out_val2 = str(h_out_val)[2:]
        len_val2 = len(h_out_val2)
        
        if len_val2 % 2 != 0:
            h_out_val2 = "0" + h_out_val2
            
        
        len_val2 = len(h_out_val2)
        zero_val = 8 - len_val2
        print("zeros: " + str(zero_val))
        if len_val2 < 8:
            zeros = ""
            for i in range(zero_val):
                zeros += "0"
            h_out_val2 = zeros + h_out_val2
        

        o_entry2.delete(0,tk.END)
        o_entry2.insert(0,h_out_val2)  
        
        
        # OUTPUT 3
        n = 2
        val3_arr = [h_out_val2[i:i+n] for i in range(0, len(h_out_val2), n)]
        len_arr = len(val3_arr)
        
        h_out_val3 = ""
        for i in range(len_arr):
            temp_val = val3_arr.pop()
            h_out_val3 += temp_val
            
        o_entry3.delete(0,tk.END)
        o_entry3.insert(0,h_out_val3)  
        
    elif str_mode == "M2": # HEX --> DEC
        in_val = i_entry.get()
        
        try:
            out_hex_str = int(in_val, 16)
            o_entry.delete(0,tk.END)
            o_entry.insert(0,out_hex_str)   
            
            o_entry2.delete(0,tk.END)
            o_entry2.insert(0,"")   
            
            o_entry3.delete(0,tk.END)
            o_entry3.insert(0,"")               
        except:
            tk.messagebox.showwarning("Conversion Error #2", "This is not a valid hex value to convert!")
            return
        
    
    o_entry['state'] = 'readonly'   
    o_entry2['state'] = 'readonly'   
    o_entry3['state'] = 'readonly'   


main()