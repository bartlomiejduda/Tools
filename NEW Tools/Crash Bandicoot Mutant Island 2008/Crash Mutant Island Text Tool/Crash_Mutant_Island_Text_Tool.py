# -*- coding: utf-8 -*-

# Tested on Python 3.7.3
# This tool should be used with Crash Mutant Island 2008 Java game

# Ver    Date        Name
# v1.0   09.10.2019  Bartlomiej Duda
# v1.1   10.10.2019  Bartlomiej Duda
# v1.2   11.10.2019  Bartlomiej Duda
# v1.3   12.10.2019  Bartlomiej Duda


VERSION_NUM = "v1.3"


import os
import sys
import struct
import tkinter as tk
from tkinter import messagebox, StringVar, OptionMenu, filedialog, ttk, Text, LabelFrame, Radiobutton
import webbrowser


current_mode = "M1"
txtpackfile_path = ""
txtfile_path = ""

def convert_M1(p_input_textfile_path, p_output_filepath):
    print ("Starting Crash Java text convert...")
    
    strings_arr = []
    text_file = open(p_input_textfile_path, 'rb')
    output_text_file = open(p_output_filepath, 'wb+')
    
    num_of_bytes_to_skip = struct.unpack('>H', text_file.read(2))[0]
    text_file.read(num_of_bytes_to_skip)
    
    f_count = 0
    s_count = 0
    for j in range(6):
        f_count += 1
        short2_count_start = struct.unpack('>H', text_file.read(2))[0]
        short1_count_end = struct.unpack('>H', text_file.read(2))[0]        
        for i in range(short1_count_end):
            s_count += 1
            curr_offset = text_file.tell()
            string_size = struct.unpack('>H', text_file.read(2))[0]
            text_string = text_file.read(string_size)
            
            text_string = ( text_string
                            .replace(b"\xef\xbf\xbf\xc0\x80", b"<special_str_01>")
                            .replace(b"\xef\xbf\xbf\x03", b"<special_str_03>")
                            .replace(b"\xef\xbf\xbf\x04", b"<special_str_04>")
                            .replace(b"\xef\xbf\xbf\x05", b"<special_str_05>")
                            .replace(b"\xef\xbf\xbf\x06", b"<special_str_06>")
                            .replace(b"\xef\xbf\xbf\x08", b"<special_str_08>")
                            .replace(b"A\xc3\x86\xc3\x82\xc3\x80BC\xc3\x87DE\xc3\x89\xc3\x8a\xc3\x88\xc3\x8bFGHI\xc3\x8e\xc3\x8fJKLMNO\xc5\x92\xc3\x94PQRSTU\xc3\x9b\xc3\x99\xc3\x9c\xc2\xa9\xc2\xae\xe2\x84\xa2\xc3\x80BCDE\xc3\x89\xc3\x88FGHI\xc3\x8cJKLMNO\xc3\x92&lt;&gt;+-,.:()\xc2\xa9\xc2\xae\xe2\x84\xa2\xc3\x84\xc3\x96\xc3\x9c\xc3\x81\xc3\x89\xc3\x8d\xc3\x91\xc3\x93\xc3\x9a", b"<special_str_LONG>")
                            .replace(b"\xc2\xa9", b"<special_str_SHORT>")
                            .replace(b"\n", b"<special_str_new_line>")
                           )
            
            #print("f=" + str(f_count) + " s=" + str(s_count) + " i=" + str(i+1) + " string_size = " + str(string_size) + " curr_offset = " + str(curr_offset)  )
            #print(text_string)
            output_text_file.write(text_string)
            output_text_file.write(b"\x0D\x0A")
        
    text_file.close()
    output_text_file.close()
    print ("Ending Crash Java text convert...")
    

def open_manual():
    filename = "crash_text_tool_manual.html"
    webbrowser.open('file://' + os.path.realpath(filename))
    
def callback(url):
    webbrowser.open_new(url)


def about_window(self):
        t = tk.Toplevel(self)
        t.wm_title("About")
        
        a_text = ( "Crash Mutant Island Text Tool\n"
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


def b_browse(option):
    global txtpackfile_path
    global txtfile_path
    
    
    if option == 1:
        if current_mode == "M1":
            txtpackfile_path =  filedialog.askopenfilename(initialdir = ".",title = "Select Txt-Pack file", initialfile="Txts_Pack_nb_0")
        elif current_mode == "M2":
            txtpackfile_path =  filedialog.asksaveasfilename(initialdir = ".",title = "Save Txt-Pack file", initialfile="Txts_Pack_nb_0")
            
        if txtpackfile_path != '':
            txt_pack_text.delete(1.0,"end-1c")
            txt_pack_text.insert("end-1c", txtpackfile_path)             
            
            
    elif option == 2:
        if current_mode == "M1":
            txtfile_path = filedialog.asksaveasfilename(initialdir = ".",title = "Save TXT file", initialfile="output.txt")
        elif current_mode == "M2":
            txtfile_path = filedialog.askopenfilename(initialdir = ".",title = "Select TXT file", initialfile="output.txt")

        if txtfile_path != '':
            txt_text.delete(1.0,"end-1c")
            txt_text.insert("end-1c", txtfile_path)  



WINDOW_HEIGHT = 230
WINDOW_WIDTH = 500


root = tk.Tk("Crash Mutant Island Text Tool", "Crash Mutant Island Text Tool")
root.winfo_toplevel().title("Crash Mutant Island Text Tool " + VERSION_NUM)

try:
    root.iconbitmap('crash_t_icon.ico')
except:
    print("Icon not loaded!")


canvas = tk.Canvas(root, height=WINDOW_HEIGHT, width=WINDOW_WIDTH)
canvas.pack()

main_frame = tk.Frame(root, bg='light blue', bd=5)
main_frame.place(relx=0.01, rely=0.01, relwidth=0.98, relheight=0.98)



txt_pack_label = tk.Label(main_frame, text="Txt-Pack filepath")
txt_pack_label.place(relx=0.01, rely=0.1, relwidth=0.2, height=20)
txt_pack_text = tk.Text(main_frame, font=("Arial", 10), wrap='none')
txt_pack_text.place(relx= 0.01, rely= 0.2, relwidth=0.65, height=20)
txt_pack_button = tk.Button(main_frame, text="Browse", command=lambda: b_browse(1))
txt_pack_button.place(relx= 0.69, rely= 0.2, relwidth=0.2, height=20)


txt_label = tk.Label(main_frame, text="TXT filepath")
txt_label.place(relx=0.01, rely=0.35, relwidth=0.2, height=20)
txt_text = tk.Text(main_frame, font=("Arial", 10), wrap='none')
txt_text.place(relx= 0.01, rely= 0.45, relwidth=0.65, height=20)
txt_button = tk.Button(main_frame, text="Browse", command=lambda: b_browse(2))
txt_button.place(relx= 0.69, rely= 0.45, relwidth=0.2, height=20)


class Path_Exception(Exception):
    pass

def convert():
    fkt = ""
    c_txt_pack_path = txt_pack_text.get("1.0","end-1c")
    c_txt_path = txt_text.get("1.0","end-1c")
    
    try: #validation
        
        if len(c_txt_pack_path) < 3 or len(c_txt_path) < 3:
            fkt = "TOO_SHORT"
            raise Path_Exception
        
        if (not os.path.exists(c_txt_pack_path) and current_mode == "M1")  or  (not os.path.exists(c_txt_path) and current_mode == "M2"):
            fkt = "INV_PATH"
            raise Path_Exception
        
    except Path_Exception:
        err_msg = ( "Error code: " + fkt + "\n"
                    "Invalid paths! Please input correct\n"
                    "paths for Txt-Pack and TXT files.")
            
        messagebox.showerror("ERROR", err_msg) 
        return
    
    if current_mode == "M1":
        try:
            convert_M1(c_txt_pack_path, c_txt_path)
            sys.stdout.flush()
            messagebox.showinfo("Info", "File converted successfully!")
        except:
            err_msg = ("Error occurred during conversion from Txt-Pack to TXT!")
            messagebox.showerror("ERROR", err_msg) 
    
    #print("path1: " +  c_txt_pack_path)
    #print("path2: " + c_txt_path)
    sys.stdout.flush()

convert_to_txt_button = tk.Button(main_frame, text="Convert Txt-Pack to TXT", command=lambda: convert())
convert_to_txt_button.place(relx= 0.1, rely= 0.72, relwidth=0.32, height=20)



def change_mode(mode_str):
    global current_mode
    current_mode = mode_str
    print("Current mode: " + current_mode)
    sys.stdout.flush()
    
    if current_mode == "M1":
        convert_to_txt_button['text'] = "Convert Txt-Pack to TXT"
    elif current_mode == "M2":
        convert_to_txt_button['text'] = "Convert TXT to Txt-Pack"

mode_frame = LabelFrame(main_frame, text="Select Mode", padx=5, pady=5)
mode_frame['bg'] = mode_frame.master['bg']
mode_frame.place(relx= 0.5, rely= 0.6, relwidth=0.28, relheight=0.34)
v = StringVar()
v.set("M1")
radio_b_1 = Radiobutton(mode_frame, text="Txt-Pack to TXT", variable=v, value="M1", bg="light blue", command=lambda: change_mode("M1")).pack()
radio_b_2 = Radiobutton(mode_frame, text="TXT to Txt-Pack", variable=v, value="M2", bg="light blue", command=lambda: change_mode("M2")).pack()



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