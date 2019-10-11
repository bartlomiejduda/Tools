# -*- coding: utf-8 -*-

# Tested on Python 3.7.3
# This tool should be used with Crash Mutant Island 2008 Java game

# Ver    Date        Name
# v1.0   09.10.2019  Bartlomiej Duda
# v1.1   10.10.2019  Bartlomiej Duda
# v1.2   11.10.2019  Bartlomiej Duda


VERSION_NUM = "v1.2"


import os
import sys
import struct
import tkinter as tk
from tkinter import messagebox, StringVar, OptionMenu, filedialog, ttk, Text
import webbrowser


def open_text():
    print ("Starting Crash Java text load...")
    
    strings_arr = []
    p_input_textfile_path = "C:\\Users\\Adam\\Desktop\\Txts_Pack_nb_2"
    text_file = open(p_input_textfile_path, 'rb')
    output_text_file = open("out.txt", 'wb+')
    
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
            
            print("f=" + str(f_count) + " s=" + str(s_count) + " i=" + str(i+1) + " string_size = " + str(string_size) + " curr_offset = " + str(curr_offset)  )
            print(text_string)
            output_text_file.write(text_string)
            output_text_file.write(b"\x0D\x0A")
        
    text_file.close()
    output_text_file.close()
    
#open_text()

def open_manual():
    filename = "crash_text_tool_manual.html"
    webbrowser.open('file://' + os.path.realpath(filename))


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







WINDOW_HEIGHT = 200
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
txt_pack_text = tk.Text(main_frame, font=40)
txt_pack_text.place(relx= 0.01, rely= 0.22, relwidth=0.65, height=20)
txt_pack_button = tk.Button(main_frame, text="Browse", command=lambda: b_browse(1))
txt_pack_button.place(relx= 0.69, rely= 0.22, relwidth=0.2, height=20)


txt_label = tk.Label(main_frame, text="TXT filepath")
txt_label.place(relx=0.01, rely=0.4, relwidth=0.2, height=20)
txt_text = tk.Text(main_frame, font=40)
txt_text.place(relx= 0.01, rely= 0.52, relwidth=0.65, height=20)
txt_button = tk.Button(main_frame, text="Browse", command=lambda: b_browse(2))
txt_button.place(relx= 0.69, rely= 0.52, relwidth=0.2, height=20)


convert_to_txt_button = tk.Button(main_frame, text="Convert Txt-Pack to TXT", command=lambda: convert_txt_pack_to_txt())
convert_to_txt_button.place(relx= 0.1, rely= 0.72, relwidth=0.32, height=20)
convert_to_txt_pack_button = tk.Button(main_frame, text="Convert TXT to Txt-Pack", command=lambda: convert_txt_to_txt_pack())
convert_to_txt_pack_button.place(relx= 0.5, rely= 0.72, relwidth=0.32, height=20)





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