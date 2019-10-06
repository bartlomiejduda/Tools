# -*- coding: utf-8 -*-

# Tested on Python 3.7.3
# This tool should be used with Crash Mutant Island 2008 Java game

# Ver    Date        Name
# v1.0   27.09.2019  Bartlomiej Duda
# v1.1   28.09.2019  Bartlomiej Duda
# v1.2   29.09.2019  Bartlomiej Duda
# v1.3   30.09.2019  Bartlomiej Duda
# v1.4   01.10.2019  Bartlomiej Duda
# v1.5   02.10.2019  Bartlomiej Duda
# v1.6   03.10.2019  Bartlomiej Duda
# v1.7   03.10.2019  Bartlomiej Duda
# v1.8   03.10.2019  Bartlomiej Duda
# v1.9   04.10.2019  Bartlomiej Duda
# v1.10  05.10.2019  Bartlomiej Duda
# v1.11  05.10.2019  Bartlomiej Duda
# v1.12  06.10.2019  Bartlomiej Duda
# v1.13  07.10.2019  Bartlomiej Duda

VERSION_NUM = "v1.13"



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
from tkinter import messagebox, StringVar, OptionMenu, filedialog, ttk
from tkintertable import TableCanvas, TableModel, Preferences
import traceback
from PIL import Image, ImageTk  #"pip install Pillow" for this!
import webbrowser



header_dict = {}
char_dict = {}
sp_char_dict = {}
global_font_path = ""
font_loaded_flag = False
special_char_data = None

def font_load(p_input_fontfile_path):
    print ("Starting Crash Java font load...")
    
    font_file = open(p_input_fontfile_path, 'rb')
    #log_file = open("out_log.txt", "wt+")
    
    
    #read header
    magic = struct.unpack('3s', font_file.read(3))[0]
    if str(magic.decode("utf-8")) != "FAC":
        return -1
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
    back_offset = font_file.tell()
    for j in range(num_special_chars): #read special character table
        current_offset = font_file.tell()
        special_character = struct.unpack('>H', font_file.read(2))[0]
        width = struct.unpack('>B', font_file.read(1))[0]
        height = struct.unpack('>B', font_file.read(1))[0]  
        posBase = struct.unpack('>B', font_file.read(1))[0]
        is_special_char = n
        loop_string_all = ""
        for k in range(2):
            index = struct.unpack('>H', font_file.read(2))[0]
            XOffset = struct.unpack('>B', font_file.read(1))[0]
            YOffset = struct.unpack('>B', font_file.read(1))[0]
            n += 1
            loop_string = ( "index: " + str(index) + " XOffset: " + str(XOffset) + " YOffset: " + str(YOffset) + '; ')
            loop_string_all += loop_string
                    
        log_string = (str(j+1) + ") sp_char: " + str(chr(special_character)) + " width: " + str(width) + 
              " height: " + str(height) + " posBase: " + str(posBase) + 
              " is_special: " + str(is_special_char) + " curr_offset: " + str(current_offset) + '\n' + loop_string_all)  
        #print(log_string)
        
        sp_row_char_dict = {}
        sp_row_char_dict['Special character'] = str(chr(special_character))
        sp_row_char_dict['Width'] = width
        sp_row_char_dict['Height'] = height
        sp_row_char_dict['Position Base'] = posBase
        sp_row_char_dict['Is_special_char'] = is_special_char
        sp_row_char_dict['loop_string_all'] = loop_string_all
        sp_char_dict['rec' + str(j+1)] = sp_row_char_dict   
        
    font_file.seek(back_offset)
    global special_char_data
    special_char_data = font_file.read()
    
    #log_file.close()
    font_file.close()
    print("Ending Crash Java font load...")
    return 0



def donothing():
    print("Do nothing")
    
def open_manual():
    filename = "crash_font_tool_manual.html"
    webbrowser.open('file://' + os.path.realpath(filename))
    

    
def about_window(self):
        t = tk.Toplevel(self)
        t.wm_title("About")
        
        a_text = ( "Crash Mutant Island Font Tool\n"
                   "Version: " + VERSION_NUM + "\n"
                   "\n"
                   "Program has been created\n"
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
root.winfo_toplevel().title("Crash Mutant Island Font Tool " + VERSION_NUM)

try:
    root.iconbitmap('crash_f_icon.ico')
except:
    print("Icon not loaded!")


canvas = tk.Canvas(root, height=WINDOW_HEIGHT, width=WINDOW_WIDTH)
canvas.pack()

header_frame = tk.Frame(root, bg='light blue', bd=5)
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
h_topdec_text = tk.Text(header_frame, font=40)
h_topdec_text.place(rely= 0.6, relx= 0.2, relwidth=0.15, height=20)

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
character_frame.place(relx=0.01, rely=0.32, relwidth=0.98, relheight=0.37)

sp_character_frame = tk.Frame(root, bg='light blue', bd=10)
sp_character_frame.place(relx=0.01, rely=0.7, relwidth=0.98, relheight=0.28)

ch_label = tk.Label(character_frame, text="Character table")
ch_label.place(relwidth=0.15, height=20)

sp_ch_label = tk.Label(sp_character_frame, text="Special character table (read-only)")
sp_ch_label.place(relwidth=0.28, height=20)

ch_button_add = tk.Button(character_frame, text="Add", command=lambda: b_add_row())
ch_button_add.place(relwidth=0.15, height=20, relx=0.4)

ch_button_delete = tk.Button(character_frame, text="Delete", command=lambda: b_delete_row())
ch_button_delete.place(relwidth=0.15, height=20, relx=0.57)

ch_button_preview = tk.Button(character_frame, text="Preview", command=lambda: get_preview(root))
ch_button_preview.place(relwidth=0.15, height=20, relx=0.74)

zoom_var = StringVar(character_frame)
zoom_var.set("x1")
zoom_list = OptionMenu(character_frame, zoom_var, "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10")
zoom_list.place(relwidth=0.07, height=20, relx=0.9)



ch_frame = tk.Frame(character_frame, bg='light blue')
ch_frame.place(relx=0.01, rely=0.2, relwidth=0.99, relheight=0.84)

sp_ch_frame = tk.Frame(sp_character_frame, bg='light blue')
sp_ch_frame.place(relx=0.01, rely=0.2, relwidth=0.99, relheight=0.84)

model = TableModel()
table = TableCanvas(ch_frame, model=model)
table.show()

model2 = TableModel()
table2 = TableCanvas(sp_ch_frame, model=model2, read_only=True)
table2.show()


def b_add_row():
    global font_loaded_flag
    if font_loaded_flag == False:
        print("Can't add new row! Font is not loaded!")
    else:
        try:
            num_ch = int(h_numofchars_text.get("1.0","end-1c"))
            num_ch += 1
            h_numofchars_text.configure(state='normal')
            h_numofchars_text.delete(1.0,"end-1c")
            h_numofchars_text.insert("end-1c", num_ch) 
            h_numofchars_text.configure(state='disabled')        
        except Exception as e:
            print("Add row value error: " + str(e))
            traceback.print_exc()
            
        table.addRow()
        table.redraw()    
    sys.stdout.flush()
        
    
def b_delete_row():
    global font_loaded_flag
    if font_loaded_flag == False:
        print("Can't delete rows! Font is not loaded!")
    else:    
        try:
            count_rows = len(table.multiplerowlist)
            if count_rows > 1:
                rows = table.multiplerowlist
                table.model.deleteRows(rows)
                table.clearSelected()
                table.setSelectedRow(0)    
            else:
                row = table.getSelectedRow()
                table.model.deleteRow(row)
                table.setSelectedRow(row-1)
                table.clearSelected()  
        except Exception as e:
            print("Delete row error: " + str(e)) 
            traceback.print_exc()        
            
        try:
            num_ch = int(h_numofchars_text.get("1.0","end-1c"))
            num_ch -= count_rows
            h_numofchars_text.configure(state='normal')
            h_numofchars_text.delete(1.0,"end-1c")
            h_numofchars_text.insert("end-1c", num_ch) 
            h_numofchars_text.configure(state='disabled')        
        except Exception as e:
            print("Delete row value error: " + str(e)) 
            traceback.print_exc()
    
        table.redraw()
    sys.stdout.flush()
         

class PNG_Exception(Exception):
    pass    

def get_preview(self):
    prev_window_init = False
    global font_loaded_flag
    if font_loaded_flag == False:
        messagebox.showinfo("Info", "No preview available")
    else:
        try:
            png_file_path = str(global_font_path + ".png")
            print("PNG open... " + png_file_path)
            
            zoom_var_f = int(zoom_var.get().lstrip("x"))
            RESIZE_PARAM = zoom_var_f
            
            t = tk.Toplevel(self, bg='grey')
            prev_window_init = True
            t.wm_title("Preview")
            
        
            
            try:
                image = Image.open(png_file_path)
            except:
                t.destroy()
                raise PNG_Exception
            [imageSizeWidth, imageSizeHeight] = image.size
            image = image.resize((RESIZE_PARAM*imageSizeWidth, RESIZE_PARAM*imageSizeHeight), Image.ANTIALIAS)            
            image.save("temp.png")
            
            data = table.model.data
            p_row = table.getSelectedRow()
            p_row_name = model.getRecName(p_row)
            
            p_height = data[p_row_name]['Height']
            p_width = data[p_row_name]['Width']
            p_posX = data[p_row_name]['PositionX']
            p_posY = data[p_row_name]['PositionY']
            
            print("H: " + str(p_height) + " W: " + str(p_width) + " posX: " + str(p_posX) + " posY: " + str(p_posY) )
            
            
            prev_canvas = tk.Canvas(t, bg='black', bd=0, highlightthickness=0, relief='ridge')
            prev_canvas.font_image_png = ImageTk.PhotoImage(file="temp.png")
            prev_canvas.create_image(0, 0, image=prev_canvas.font_image_png, anchor='nw')
            
            posX_2 = (p_posX + p_width)*RESIZE_PARAM
            posY_2 = (p_posY + p_height)*RESIZE_PARAM
            prev_canvas.create_rectangle(RESIZE_PARAM*p_posX, RESIZE_PARAM*p_posY, posX_2, posY_2, outline='red')
            prev_canvas.config(width=prev_canvas.font_image_png.width(), height=prev_canvas.font_image_png.height())
            prev_canvas.pack()
            

            
            os.remove("temp.png")
        
        except PNG_Exception:
            err_msg = ( "Couldn't load PNG font image!\n"
                        "Please put it in the same folder as\n"
                        "font file and try again." )
            messagebox.showinfo("Info", err_msg)
            traceback.print_exc()            
            
        except:
            if prev_window_init == True:
                t.destroy()
            messagebox.showinfo("Info", "Couldn't load preview!")
            traceback.print_exc()
        finally:
            sys.stdout.flush()


def open_font():
    #p_input_fontfile_path = 'C:\\Users\\Adam\\Desktop\\CRASH_JAVA_FILES\\Font_nb_0'
    p_input_fontfile_path =  filedialog.askopenfilename(initialdir = ".",title = "Select file")
    print ("Opening font file... " + p_input_fontfile_path)   
    
    if p_input_fontfile_path == '':
        print("No font file to open...")
        sys.stdout.flush()
        return
    
    
    global global_font_path
    global_font_path = p_input_fontfile_path
    load_res = font_load(p_input_fontfile_path)
    if load_res != 0:
        sys.stdout.flush()
        err_string = ( "This is not a proper Crash Mutant Island Font file!\n"
                       "Please choose proper font file." )
        messagebox.showerror("ERROR", err_string) 
        return
    
    
    global font_loaded_flag
    font_loaded_flag = True
    
    h_magic_text.configure(state='normal')
    h_magic_text.delete(1.0,"end-1c")
    h_magic_text.insert("end-1c", header_dict.get('Magic'))
    h_magic_text.configure(state='disabled')
    
    h_fontheight_text.delete(1.0,"end-1c")
    h_fontheight_text.insert("end-1c", header_dict.get('Font height'))
    
    h_topdec_text.delete(1.0,"end-1c")
    h_topdec_text.insert("end-1c", header_dict.get('TopDec'))   
    
    h_spacewidth_text.delete(1.0,"end-1c")
    h_spacewidth_text.insert("end-1c", header_dict.get('Space width'))    
    
    h_numofchars_text.configure(state='normal')
    h_numofchars_text.delete(1.0,"end-1c")
    h_numofchars_text.insert("end-1c", header_dict.get('num_chars')) 
    h_numofchars_text.configure(state='disabled')
    
    h_numofspchars_text.configure(state='normal')
    h_numofspchars_text.delete(1.0,"end-1c")
    h_numofspchars_text.insert("end-1c", header_dict.get('num_special_chars'))     
    h_numofspchars_text.configure(state='disabled')
    
    model = table.model
    model.deleteRows()
    model.importDict(char_dict) 
    
    model2 = table2.model
    model2.deleteRows()
    model2.importDict(sp_char_dict)    
    
    if font_loaded_flag == True:
        filemenu.entryconfig(1, state="normal") #Save
        filemenu.entryconfig(2, state="normal") #Save as
        filemenu.entryconfig(3, state="normal") #Close        

    sys.stdout.flush()
    table.redraw()
    table2.redraw()

def close_font():
    global font_loaded_flag
    font_loaded_flag = False
    
    h_magic_text.configure(state='normal')
    h_magic_text.delete(1.0,"end-1c")
    h_magic_text.configure(state='disabled')
    
    h_fontheight_text.delete(1.0,"end-1c")
    
    h_topdec_text.delete(1.0,"end-1c") 
    
    h_spacewidth_text.delete(1.0,"end-1c")   
    
    h_numofchars_text.configure(state='normal')
    h_numofchars_text.delete(1.0,"end-1c")
    h_numofchars_text.configure(state='disabled')
    
    h_numofspchars_text.configure(state='normal')
    h_numofspchars_text.delete(1.0,"end-1c")   
    h_numofspchars_text.configure(state='disabled')   
    
    model = table.model
    model.deleteRows()
    
    model2 = table2.model
    model2.deleteRows()  
    
    if font_loaded_flag == False:
        filemenu.entryconfig(1, state="disabled") #Save
        filemenu.entryconfig(2, state="disabled") #Save as
        filemenu.entryconfig(3, state="disabled") #Close        

    sys.stdout.flush()
    table.redraw()
    table2.redraw()    
    
def save_as_font():

    #data validation
    try:
        fkt_row = ""
        fkt_col = ""  
        value = None
        fkt = "MAGIC"
        magic_t = h_magic_text.get("1.0","end-1c").rstrip('\n').encode()
        fkt = "FONT HEIGHT"
        font_height_i = int(h_fontheight_text.get("1.0","end-1c").rstrip('\n'))
        if font_height_i < 0 or font_height_i > 255:
            raise Exception
        fkt = "TOP DEC"
        top_dec_i = int(h_topdec_text.get("1.0","end-1c").rstrip('\n'))
        if top_dec_i < 0 or top_dec_i > 255:
            raise Exception        
        fkt = "SPACE WIDTH"
        space_width_i = int(h_spacewidth_text.get("1.0","end-1c").rstrip('\n'))
        if space_width_i < 0 or space_width_i > 255:
            raise Exception 
        fkt = "NUM OF CHARS"
        num_of_chars_i = int(h_numofchars_text.get("1.0","end-1c").rstrip('\n'))
        if num_of_chars_i < 0 or num_of_chars_i > 255:
            raise Exception 
        fkt = "NUM OF SPECIAL CHARS"
        num_of_sp_chars_i = int(h_numofspchars_text.get("1.0","end-1c").rstrip('\n'))
        if num_of_sp_chars_i < 0 or num_of_sp_chars_i > 255:
            raise Exception         
        
        fkt = "CHARACTER TABLE"
        count_rows = model.getRowCount()
        data = table.model.data
        cols = table.model.columnNames  
        for col in cols:
            fkt_col = col
            for i in range(count_rows):
                fkt_row = i+1
                value = data[model.getRecName(i)][col]
                if col == 'Character':
                    if len(str(value)) != 1:
                        print("Val: " + str(value) + " Len: " + str(len(value)))
                        raise Exception
                else:
                    temp_i = int(value)
                    if col != 'Is_special_char':
                        if temp_i < 0:
                            raise Exception
                #print("data[rec" + str(i+1) + "][" + col + "] = " + str(value))
        sys.stdout.flush()
        
        
    except Exception as e:
        if fkt == "CHARACTER TABLE":
            err_string = ("Couldn't validate " + fkt + ". Please input correct data.\n"
                          "Incorrect value in column \"" + str(fkt_col) + "\" and row \"" + str(fkt_row) + "\".")
        else:
            err_string = ("Couldn't validate " + fkt + " field in header section. Please input correct data." )
                          
        traceback.print_exc()
        print("fkt = " + str(fkt) + " fkt_col = " + str(fkt_col) + " fkt_row = " + str(fkt_row) + " value = " + str(value) + " len_value = " + str(len(str(value))))
        sys.stdout.flush()
        messagebox.showerror("ERROR", err_string)
        return
    
    
    root.filename =  filedialog.asksaveasfilename(initialdir = ".",title = "Save Crash font file", initialfile="Font_nb_0")
    print (root.filename)
    sys.stdout.flush()
    
    #saving font data
    if root.filename != '':
        font_file = open(root.filename, 'wb+')
        print("Saving font data to " + str(root.filename) )
        
        try:
            #header
            fkt = "HEADER WRITE"
            font_file.write(struct.Struct("3s").pack(magic_t))
            font_file.write(struct.Struct(">B").pack(font_height_i))
            font_file.write(struct.Struct(">B").pack(top_dec_i))
            font_file.write(struct.Struct(">B").pack(space_width_i))
            font_file.write(struct.Struct(">H").pack(num_of_chars_i))
            font_file.write(struct.Struct(">H").pack(num_of_sp_chars_i))
            
            #character table
            fkt_row = 0
            fkt_col = ""
            fkt = "CHARACTER TABLE WRITE"
            count_rows = model.getRowCount()
            data = table.model.data  
            for i in range(count_rows):
                fkt_row = i+1
                fkt_col = "Character"
                value = data[model.getRecName(i)]['Character']
                font_file.write(struct.Struct(">H").pack(ord(value)))
                fkt_col = "Width"
                value = data[model.getRecName(i)]['Width']
                font_file.write(struct.Struct(">B").pack(int(value)))
                fkt_col = "Height"
                value = data[model.getRecName(i)]['Height']
                font_file.write(struct.Struct(">B").pack(int(value)))  
                fkt_col = "PositionX"
                value = data[model.getRecName(i)]['PositionX']
                font_file.write(struct.Struct(">B").pack(int(value)))  
                fkt_col = "PositionY"
                value = data[model.getRecName(i)]['PositionY']
                font_file.write(struct.Struct(">B").pack(int(value))) 
                fkt_col = "Position Base"
                value = data[model.getRecName(i)]['Position Base']
                font_file.write(struct.Struct(">B").pack(int(value)))                                
                     
                     
            #special character table  
            fkt = "SPECIAL CHARACTER TABLE WRITE"
            font_file.write(special_char_data)            
                    
        except:
            err_string = ( "Error occured in section " + str(fkt) + ".\n" )
            if fkt == "CHARACTER TABLE WRITE":
                err_string += ( "Row number: " + str(fkt_row) + "\n" )
                err_string += ( "Column: " + str(fkt_col) + "\n" )
            messagebox.showerror("ERROR", err_string)
            traceback.print_exc()
        
        
        sys.stdout.flush()    
        font_file.close()

char_dict = {'rec1': {'Character': None, 'Width': None, 'Height': None, 'PositionX': None, 'PositionY': None, 'Position Base': None, 'Is_special_char': None} } 
sp_char_dict = {'rec1': {'Special character': None, 'Width': None, 'Height': None, 'Position Base': None, 'Is_special_char': None, 'loop_string_all': None} } 

model = table.model
model.importDict(char_dict)  

model2 = table2.model
model2.importDict(sp_char_dict)  


try:
    table.resizeColumn(5, 130) #Position Base
    table.resizeColumn(6, 150) #Is_special_char
    table2.resizeColumn(0, 150) #Special character
    table2.resizeColumn(3, 150) #Position Base
    table2.resizeColumn(4, 150) #Is_special_char
    table2.resizeColumn(5, 550) #loop_string_all
except:
    print("Couldn't resize columns!")
table.redraw()







menubar = tk.Menu(root)

filemenu = tk.Menu(menubar, tearoff=0)
filemenu.add_command(label="Open", command=lambda: open_font())
filemenu.add_command(label="Save", command=donothing)
filemenu.add_command(label="Save as...", command=lambda: save_as_font())
filemenu.add_command(label="Close", command=lambda: close_font())
filemenu.add_separator()
filemenu.add_command(label="Exit", command=root.destroy)
menubar.add_cascade(label="File", menu=filemenu)

helpmenu = tk.Menu(menubar, tearoff=0)
helpmenu.add_command(label="Manual", command=lambda: open_manual())
helpmenu.add_command(label="About...", command=lambda: about_window(root))
menubar.add_cascade(label="Help", menu=helpmenu)


filemenu.entryconfig(1, state="disabled") #Save
filemenu.entryconfig(2, state="disabled") #Save as
filemenu.entryconfig(3, state="disabled") #Close

root.config(menu=menubar)


root.mainloop()