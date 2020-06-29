# -*- coding: utf-8 -*-

# Tested on Python 3.8.0

# Ver    Date        Name               Comment
# v0.1   08.01.2020  Bartlomiej Duda    -
# v0.2   23.06.2020  Bartlomiej Duda    -
# v0.3   26.06.2020  Bartlomiej Duda    -
# v0.4   27.06.2020  Bartlomiej Duda    -
# v0.5   29.06.2020  Bartlomiej Duda    -



VERSION_NUM = "v0.5"


import os
import sys
import struct
import tkinter as tk
from tkinter import messagebox, StringVar, OptionMenu, filedialog, ttk, Text, LabelFrame, Radiobutton
from PIL import ImageTk, Image
import webbrowser
import traceback



def bd_logger(in_str):
    import datetime
    now = datetime.datetime.now()
    print(now.strftime("%d-%m-%Y %H:%M:%S") + " " + in_str)    



def open_manual():
    filename = "bdtexview_manual.html"
    webbrowser.open('file://' + os.path.realpath(filename))
    
def callback(url):
    webbrowser.open_new(url)

class Path_Exception(Exception):
    pass


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




def main():
    
    #default app settings
    WINDOW_HEIGHT = 700
    WINDOW_WIDTH = 800
    
    #default yellow canvas settings
    canv_yellow_settings = [ 10,   70,  200,   180,    0          ] 
                            #x     y    width  height  change_flag    
    
    root = tk.Tk("BDTexView", "BDTexView")
    root.winfo_toplevel().title("BDTexView " + VERSION_NUM)
    
    try:
        root.iconbitmap('bdtexview_icon.ico')
    except:
        bd_logger("Icon not loaded!")
    
    
    
    
    #main window
    canvas = tk.Canvas(root, height=WINDOW_HEIGHT, width=WINDOW_WIDTH)
    canvas.pack()
    main_frame = tk.Frame(root, bg='light blue', bd=5)
    main_frame.place(x=0, y=0, relwidth=1, relheight=1)
    
    
    
    
    
    #browse image
    txt_pack_label = tk.Label(main_frame, text="Graphic filepath")
    txt_pack_label.place(x=10, y=10, width=100, height=20)
    txt_pack_text = tk.Text(main_frame, font=("Arial", 10), wrap='none')
    txt_pack_text.place(x= 10, y= 40, width=500, height=20)
    txt_pack_button = tk.Button(main_frame, text="Browse", command=lambda: b_browse(1))
    txt_pack_button.place(x= 520, y= 40, width=100, height=20)
    
    
    

    
    #PIXEL FORMATS
    mode_frame = LabelFrame(main_frame, text="Pixel formats")
    mode_frame['bg'] = mode_frame.master['bg']
    mode_frame.place(relx=1, x= -210, rely= 0.15, width=200, height=400)
    v = StringVar()
    v.set("M1")
    radio_b_1 = Radiobutton(mode_frame, text="16x4 = 48+16          ", variable=v, value="P1", bg="light blue", command=lambda: change_mode("M1"))
    radio_b_1.place(relx=0, x=5, y= 10, width=110, height=20) 
    radio_b_2 = Radiobutton(mode_frame, text="16x3 = 48          ", variable=v, value="P2", bg="light blue", command=lambda: change_mode("M2"))
    radio_b_2.place(relx=0, x=5, y= 40, width=95, height=20) 
    
    
    
    
    
    #image showing 
    pilImage = Image.new( 'RGB', (250,250), "black")
    pixels = pilImage.load() # create the pixel map
    
    for i in range(pilImage.size[0]):    # for every col:
        for j in range(pilImage.size[1]):    # For every row
            pixels[i,j] = (i, j, 100) # set the colour accordingly
    
    image = ImageTk.PhotoImage(pilImage)
    
    

    
    canv_yellow = tk.Canvas(main_frame, bg='yellow')
    canv_yellow.place(x= canv_yellow_settings[0], y= canv_yellow_settings[1], width=canv_yellow_settings[2], height=canv_yellow_settings[3])
    
    item4 = canv_yellow.create_image(30, 80, image=image)
    
    
    
    
    
    #INFO
    canv_info_box = LabelFrame(main_frame, text="Info", padx=5, pady=5)
    canv_info_box['bg'] = canv_info_box.master['bg']
    canv_info_box.place(relx= 0, x=150, rely= 1, y=-120, width=135, height=110)   
    
    canv_h_label = tk.Label( canv_info_box, text="Canvas height: " + str(canv_yellow_settings[3]), anchor="w")
    canv_h_label['bg'] = canv_h_label.master['bg']
    canv_h_label.place(x= 5, y= 0, width=120, height=20)  
    
    canv_w_label = tk.Label( canv_info_box, text="Canvas width: " + str(canv_yellow_settings[2]), anchor="w")
    canv_w_label['bg'] = canv_h_label.master['bg']
    canv_w_label.place(x= 5, y= 15, width=120, height=20)      


    
        
    
    
    
    #buttons for manipulating canvas (CANVAS SIZE)
    canv_size_box = LabelFrame(main_frame, text="Canvas Size", padx=5, pady=5)
    canv_size_box['bg'] = canv_size_box.master['bg']
    canv_size_box.place(relx= 0, x=10, rely= 1, y=-120, width=135, height=110)    
    butt1 = tk.Button(canv_size_box, text="Left", command=lambda: change_canvas_width(canv_w_label, canv_yellow, canv_yellow_settings, -10) )
    butt1.place(x= 10, y= 30, width=40, height=20)    
    butt2 = tk.Button(canv_size_box, text="Right", command=lambda: change_canvas_width(canv_w_label, canv_yellow, canv_yellow_settings, 10) )
    butt2.place(x= 70, y= 30, width=40, height=20)  
    butt3 = tk.Button(canv_size_box, text="Up", command=lambda: change_canvas_height(canv_h_label, canv_yellow, canv_yellow_settings, -10) )
    butt3.place(x= 40, y= 5, width=40, height=20)     
    butt4 = tk.Button(canv_size_box, text="Down", command=lambda: change_canvas_height(canv_h_label, canv_yellow, canv_yellow_settings, 10) )
    butt4.place(x= 40, y= 55, width=40, height=20)  
    

    
    #debug buttons (DEBUG OPTIONS)
    canv_debug_box = LabelFrame(main_frame, text="Debug Options", padx=5, pady=5)
    canv_debug_box['bg'] = canv_debug_box.master['bg']
    canv_debug_box.place(relx= 1, x=-210, rely= 1, y=-180, width=200, height=100)    
    butt1 = tk.Button(canv_debug_box, text="Open Log", command=lambda: open_log() )
    butt1.place(x= 10, y= 10, width=80, height=20)    
    butt2 = tk.Button(canv_debug_box, text="File Properties", command=lambda: file_properties() )
    butt2.place(x= 10, y= 40, width=90, height=20)      
    
    
    
    #menu
    menubar = tk.Menu(root)
    
    filemenu = tk.Menu(menubar, tearoff=0)
    filemenu.add_command(label="Exit", command=root.destroy)
    menubar.add_cascade(label="File", menu=filemenu)
    
    imagemenu = tk.Menu(menubar, tearoff=0)
    imagemenu.add_command(label="Quick Image Save", command=lambda: quick_image_save())
    imagemenu.add_command(label="Save Image As...", command=lambda: save_image_as())
    imagemenu.add_command(label="Print Image", command=lambda: quick_image_save())
    menubar.add_cascade(label="Image", menu=imagemenu)    
    
    optionsmenu = tk.Menu(menubar, tearoff=0)
    optionsmenu.add_command(label="Export Settings", command=lambda: export_settings())
    optionsmenu.add_command(label="Import Settings", command=lambda: import_settings())
    menubar.add_cascade(label="Options", menu=optionsmenu)
    
    helpmenu = tk.Menu(menubar, tearoff=0)
    helpmenu.add_command(label="Manual", command=lambda: open_manual())
    helpmenu.add_command(label="About...", command=lambda: about_window(root))
    menubar.add_cascade(label="Help", menu=helpmenu)
    root.config(menu=menubar)
    
    root.mainloop()
    
 
def change_canvas_width(in_w_label, in_canvas, in_canvas_settings, step):
    in_canvas_settings[2] = in_canvas_settings[2] + step
    in_canvas.place(x= in_canvas_settings[0], y= in_canvas_settings[1], width=in_canvas_settings[2], height=in_canvas_settings[3])  
    in_w_label.config(text="Canvas width: " + str(in_canvas_settings[2]) )
    
def change_canvas_height(in_h_label, in_canvas, in_canvas_settings, step):
    in_canvas_settings[3] = in_canvas_settings[3] + step
    in_canvas.place(x= in_canvas_settings[0], y= in_canvas_settings[1], width=in_canvas_settings[2], height=in_canvas_settings[3])   
    in_h_label.config(text="Canvas height: " + str(in_canvas_settings[3]) )
 
    
    
main()