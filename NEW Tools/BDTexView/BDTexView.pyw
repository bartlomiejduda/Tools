# -*- coding: utf-8 -*-

'''
Copyright © 2020  Bartłomiej Duda
'''


# Tested on Python 3.8.0

# Ver    Date        Name               Comment
# v0.1   08.01.2020  Bartlomiej Duda    -
# v0.2   23.06.2020  Bartlomiej Duda    -
# v0.3   26.06.2020  Bartlomiej Duda    -
# v0.4   27.06.2020  Bartlomiej Duda    -
# v0.5   29.06.2020  Bartlomiej Duda    -
# v0.6   30.06.2020  Bartlomiej Duda    -
# v0.7   04.07.2020  Bartlomiej Duda    -
# v0.8   05.07.2020  Bartlomiej Duda    -
# v0.9   05.07.2020  Bartlomiej Duda    -
# v0.10  08.07.2020  Bartlomiej Duda    flag_manager, opening files
# v0.11  18.07.2020  Bartlomiej Duda    opening files, closing files, removed flag_manager
# v0.12  19.07.2020  Bartlomiej Duda    -
# v0.13  23.11.2020  Bartlomiej Duda    Rewriting main class


VERSION_NUM = "v0.13"


import os
import sys
import struct
import tkinter as tk
from tkinter import messagebox, StringVar, OptionMenu, filedialog, ttk, Text, LabelFrame, Radiobutton
from PIL import ImageTk, Image
import webbrowser
import traceback
import center_tk_window 




def bd_logger(in_str):
    from datetime import datetime
    now = datetime.now()
    print(now.strftime("%d-%m-%Y %H:%M:%S") + " " + in_str)    



def open_manual():
    filename = "files\\bdtexview_manual.html"
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



def export_settings(self):
    t = tk.Toplevel(self)
    t.wm_title("Export settings")



                            
                            
class BDTexView:
    def __init__(self, root):
        self.root = root
        
        self.MAIN_WINDOW_HEIGHT: int = 700
        self.MAIN_WINDOW_WIDTH: int = 730
        
        self.MIN_MAIN_WINDOW_HEIGHT: int = 700 
        self.MIN_MAIN_WINDOW_WIDTH: int = 730
        
        self.canv_yellow_x: int = 10
        self.canv_yellow_y: int = 40
        self.canv_yellow_width: int = 450
        self.canv_yellow_height: int = 300
        self.canv_yellow_max_width: int = 500
        self.canv_yellow_max_height: int = 490    
        
        self.LOADED_FILE = None
        self.LOADED_FILE_OPENED_FLAG = False                
        
        self.root.title("BDTexView " + VERSION_NUM)
        self.root.minsize(self.MIN_MAIN_WINDOW_WIDTH, self.MIN_MAIN_WINDOW_HEIGHT)         
        
        try:
            self.iconbitmap('files\\icon_bd.ico')
        except:
            bd_logger("Icon not loaded!")
        
        
        self.main_frame = tk.Frame(root, bg='light blue')
        self.main_frame.place(x=0, y=0, relwidth=1, relheight=1)        
        
        
        #browse image
        self.loaded_file_label = tk.Label(self.main_frame, text="Loaded file: None", anchor='w')
        self.loaded_file_label.place(x= 10, y= 10, width=5000, height=20)
        self.loaded_file_label['bg'] = self.loaded_file_label.master['bg']


        #PIXEL FORMATS
        self.pixel_formats_box = LabelFrame(self.main_frame, text="Pixel Formats")
        self.pixel_formats_box['bg'] = self.pixel_formats_box.master['bg']
        self.pixel_formats_box.place(relx=1, x= -210, rely= 0, y=75, width=200, height=400)
        v = StringVar()
        v.set("M1")
        self.radio_b_1 = Radiobutton(self.pixel_formats_box, text="16x4 = 48+16          ", variable=v, value="P1", bg="light blue", command=lambda: change_mode("M1"))
        self.radio_b_1.place(relx=0, x=5, y= 10, width=110, height=20) 
        self.radio_b_2 = Radiobutton(self.pixel_formats_box, text="16x3 = 48          ", variable=v, value="P2", bg="light blue", command=lambda: change_mode("M2"))
        self.radio_b_2.place(relx=0, x=5, y= 40, width=95, height=20) 
        
        
        #image showing 
        self.pilImage = Image.new( 'RGB', (250,250), "black")
        self.pixels = self.pilImage.load() # create the pixel map
        
        for i in range(self.pilImage.size[0]):    # for every col:
            for j in range(self.pilImage.size[1]):    # For every row
                self.pixels[i,j] = (i, j, 100) # set the colour accordingly
        
        self.image = ImageTk.PhotoImage(self.pilImage)
        
        self.canv_yellow = tk.Canvas(self.main_frame, bg='yellow')
        self.canv_yellow.place(x= self.canv_yellow_x, y= self.canv_yellow_y, width= self.canv_yellow_width, height=self.canv_yellow_height)
        
        item4 = self.canv_yellow.create_image(30, 80, image=self.image)        


        #INFO
        self.canv_info_box = LabelFrame(self.main_frame, text="Info", padx=5, pady=5)
        self.canv_info_box['bg'] = self.canv_info_box.master['bg']
        self.canv_info_box.place(relx= 0, x=150, rely= 1, y=-120, width=135, height=110)   
        
        self.canv_h_label = tk.Label( self.canv_info_box, text="Canvas height: " + str(self.canv_yellow_height), anchor="w")
        self.canv_h_label['bg'] = self.canv_h_label.master['bg']
        self.canv_h_label.place(x= 5, y= 0, width=120, height=20)  
        
        self.canv_w_label = tk.Label( self.canv_info_box, text="Canvas width: " + str(self.canv_yellow_width), anchor="w")
        self.canv_w_label['bg'] = self.canv_h_label.master['bg']
        self.canv_w_label.place(x= 5, y= 15, width=120, height=20)    





def main():

    #default app settings
    #WINDOW_HEIGHT = 700
    #WINDOW_WIDTH = 730
    
    #MIN_WINDOW_HEIGHT = 700
    #MIN_WINDOW_WIDTH = 730
    
    ##default yellow canvas settings
    #canv_yellow_settings = [ 10,   40,  450,   300,    500,         490       ] 
                            ##x     y    width  height  max_width    max_height       
    
    
    ##main window
    #root = tk.Tk("BDTexView", "BDTexView")
    #root.minsize(MIN_WINDOW_WIDTH, MIN_WINDOW_HEIGHT) 
    #root.winfo_toplevel().title("BDTexView " + VERSION_NUM)
    
    #try:
        #root.iconbitmap('files\\icon_bd.ico')
    #except:
        #bd_logger("Icon not loaded!")
    
    

    
    #main canvas
    #canvas = tk.Canvas(root, height=WINDOW_HEIGHT, width=WINDOW_WIDTH) 
    #main_frame = tk.Frame(root, bg='light blue')
    #main_frame.place(x=0, y=0, relwidth=1, relheight=1)
    
    
    
    
    
    #browse image
    #loaded_file_label = tk.Label(main_frame, text="Loaded file: None", anchor='w')
    #loaded_file_label.place(x= 10, y= 10, width=5000, height=20)
    #loaded_file_label['bg'] = loaded_file_label.master['bg']
    
    #txt_pack_text = tk.Text(main_frame, font=("Arial", 10), wrap='none')
    #txt_pack_text.place(x= 10, y= 40, width=500, height=20)
    #txt_pack_button = tk.Button(main_frame, text="Browse", command=lambda: b_browse(1))
    #txt_pack_button.place(x= 520, y= 40, width=100, height=20)
    
    
    

    
    ##PIXEL FORMATS
    #pixel_formats_box = LabelFrame(main_frame, text="Pixel Formats")
    #pixel_formats_box['bg'] = pixel_formats_box.master['bg']
    #pixel_formats_box.place(relx=1, x= -210, rely= 0, y=75, width=200, height=400)
    #v = StringVar()
    #v.set("M1")
    #radio_b_1 = Radiobutton(pixel_formats_box, text="16x4 = 48+16          ", variable=v, value="P1", bg="light blue", command=lambda: change_mode("M1"))
    #radio_b_1.place(relx=0, x=5, y= 10, width=110, height=20) 
    #radio_b_2 = Radiobutton(pixel_formats_box, text="16x3 = 48          ", variable=v, value="P2", bg="light blue", command=lambda: change_mode("M2"))
    #radio_b_2.place(relx=0, x=5, y= 40, width=95, height=20) 
    
    
    
    
    
    ##image showing 
    #pilImage = Image.new( 'RGB', (250,250), "black")
    #pixels = pilImage.load() # create the pixel map
    
    #for i in range(pilImage.size[0]):    # for every col:
        #for j in range(pilImage.size[1]):    # For every row
            #pixels[i,j] = (i, j, 100) # set the colour accordingly
    
    #image = ImageTk.PhotoImage(pilImage)
    
    

    
    #canv_yellow = tk.Canvas(main_frame, bg='yellow')
    #canv_yellow.place(x= canv_yellow_settings[0], y= canv_yellow_settings[1], width=canv_yellow_settings[2], height=canv_yellow_settings[3])
    
    #item4 = canv_yellow.create_image(30, 80, image=image)
    
    
    
    
    
    ##INFO
    #canv_info_box = LabelFrame(main_frame, text="Info", padx=5, pady=5)
    #canv_info_box['bg'] = canv_info_box.master['bg']
    #canv_info_box.place(relx= 0, x=150, rely= 1, y=-120, width=135, height=110)   
    
    #canv_h_label = tk.Label( canv_info_box, text="Canvas height: " + str(canv_yellow_settings[3]), anchor="w")
    #canv_h_label['bg'] = canv_h_label.master['bg']
    #canv_h_label.place(x= 5, y= 0, width=120, height=20)  
    
    #canv_w_label = tk.Label( canv_info_box, text="Canvas width: " + str(canv_yellow_settings[2]), anchor="w")
    #canv_w_label['bg'] = canv_h_label.master['bg']
    #canv_w_label.place(x= 5, y= 15, width=120, height=20)    
    
    
    

    
    def update_frame_width_label(in_w_label, in_w):
        in_w_label.config(text="Frame width: " + str(in_w) )
        
    def update_frame_height_label(in_h_label, in_h):
        in_h_label.config(text="Frame height: " + str(in_h) )  
        
    def frame_configure(event, in_w_label, in_h_label):
        w, h = event.width, event.height
        #print("width: " + str(w) + " height: " + str(h) ) 
        update_frame_width_label(in_w_label, w)
        update_frame_height_label(in_h_label, h)
    
    
    main_frame.update()
    mframe_h_label = tk.Label( canv_info_box, text="Frame height: " + str(main_frame.winfo_height()), anchor="w")
    mframe_h_label['bg'] = canv_h_label.master['bg']
    mframe_h_label.place(x= 5, y= 30, width=120, height=20) 
    mframe_w_label = tk.Label( canv_info_box, text="Frame width: " + str(main_frame.winfo_width()), anchor="w")
    mframe_w_label['bg'] = canv_h_label.master['bg']
    mframe_w_label.place(x= 5, y= 45, width=120, height=20)     

    main_frame.bind("<Configure>", lambda event: frame_configure(event, mframe_w_label, mframe_h_label) )
        
    
    
    
    #buttons for manipulating canvas (CANVAS SIZE)
    canv_size_box = LabelFrame(main_frame, text="Canvas Size", padx=5, pady=5)
    canv_size_box['bg'] = canv_size_box.master['bg']
    canv_size_box.place(relx= 0, x=10, rely= 1, y=-120, width=135, height=110)    
    c_butt1 = tk.Button(canv_size_box, text="Left", command=lambda: change_canvas_width(canv_w_label, canv_yellow, canv_yellow_settings, -10) )
    c_butt1.place(x= 10, y= 30, width=40, height=20)    
    c_butt2 = tk.Button(canv_size_box, text="Right", command=lambda: change_canvas_width(canv_w_label, canv_yellow, canv_yellow_settings, 10) )
    c_butt2.place(x= 70, y= 30, width=40, height=20)  
    c_butt3 = tk.Button(canv_size_box, text="Up", command=lambda: change_canvas_height(canv_h_label, canv_yellow, canv_yellow_settings, -10) )
    c_butt3.place(x= 40, y= 5, width=40, height=20)     
    c_butt4 = tk.Button(canv_size_box, text="Down", command=lambda: change_canvas_height(canv_h_label, canv_yellow, canv_yellow_settings, 10) )
    c_butt4.place(x= 40, y= 55, width=40, height=20)  
    
    
    #IMAGE OPTIONS 
    image_options_box = LabelFrame(main_frame, text="Image Options", padx=5, pady=5)
    image_options_box['bg'] = image_options_box.master['bg']
    image_options_box.place(relx= 0, x=290, rely= 1, y=-120, width=135, height=110)  
    
    im_options_label_w = tk.Label( image_options_box, text="Width", anchor="w" ) 
    im_options_label_w.place(relx= 0, x=0, rely= 0, y=0, width=60, height=15)  
    im_options_label_w['bg'] = im_options_label_w.master['bg']
    
    im_options_textbox_w = tk.Entry(image_options_box)
    im_options_textbox_w.place(relx= 0, x=45, rely= 0, y=0, width=40, height=15)  
    im_options_textbox_w.insert(0, "0")
    
    
    

    
    #options buttons (OTHER OPTIONS)
    canv_debug_box = LabelFrame(main_frame, text="Other Options", padx=5, pady=5)
    canv_debug_box['bg'] = canv_debug_box.master['bg']
    canv_debug_box.place(relx= 1, x=-210, rely= 0, y=480, width=200, height=100)    
    o_butt1 = tk.Button(canv_debug_box, text="Open Log", command=lambda: open_log() )
    o_butt1.place(x= 10, y= 10, width=80, height=20)    
    o_butt2 = tk.Button(canv_debug_box, text="File Properties", command=lambda: file_properties() )
    o_butt2.place(x= 10, y= 40, width=90, height=20)  
    o_butt3 = tk.Button(canv_debug_box, text="Swizzling", command=lambda: swizzling() )
    o_butt3.place(x= 95, y= 10, width=90, height=20)     
    
    
    
    #menu
    menubar = tk.Menu(root)
    
    filemenu = tk.Menu(menubar, tearoff=0)
    filemenu.add_command(label="Open File", command=lambda: open_file(filemenu, loaded_file_label))
    filemenu.add_command(label="Close File", command=lambda: close_file(filemenu, loaded_file_label))
    filemenu.entryconfig(1, state="disabled")
    filemenu.add_command(label="Exit", command=root.destroy)
    menubar.add_cascade(label="File", menu=filemenu)
    
    imagemenu = tk.Menu(menubar, tearoff=0)
    imagemenu.add_command(label="Quick Image Save", command=lambda: quick_image_save())
    imagemenu.add_command(label="Save Image As...", command=lambda: save_image_as())
    imagemenu.add_command(label="Print Image", command=lambda: print_image())
    imagemenu.add_command(label="Export Image Settings", command=lambda: export_image_settings())
    menubar.add_cascade(label="Image", menu=imagemenu)    
    
    optionsmenu = tk.Menu(menubar, tearoff=0)
    optionsmenu.add_command(label="Export Settings", command=lambda: export_settings(root))
    optionsmenu.add_command(label="Reset Settings", command=lambda: reset_settings())
    menubar.add_cascade(label="Options", menu=optionsmenu)
    
    helpmenu = tk.Menu(menubar, tearoff=0)
    helpmenu.add_command(label="Manual", command=lambda: open_manual())
    helpmenu.add_command(label="About...", command=lambda: about_window(root))
    menubar.add_cascade(label="Help", menu=helpmenu)
    root.config(menu=menubar)
    
    root.mainloop()



def open_file(in_menu, in_file_label):

    opened_file_path =  filedialog.askopenfilename(initialdir = ".",title = "Select file")
    if opened_file_path == "":
        bd_logger("File to open not selected...")
        sys.stdout.flush()
        return               
        
    try:
        opened_file_name = os.path.basename(opened_file_path)
        global LOADED_FILE
        global LOADED_FILE_OPENED_FLAG

        bd_logger("Opening file... " + opened_file_name) 
        bd_logger("File path: " + opened_file_path) 
        sys.stdout.flush()
        LOADED_FILE = open(str(opened_file_path), 'rb')
        bd_logger("File " + opened_file_name + " has been opened.") 
        LOADED_FILE_OPENED_FLAG = True
        in_menu.entryconfig(1, state="active")
        
        in_file_label.config(text="Loaded file: " + opened_file_name)
        
        
        sys.stdout.flush()
        return

    except Exception as e:
        bd_logger("Error while opening file...")
        traceback.print_exc()
        sys.stdout.flush()
        return       


def close_file(in_menu, in_file_label):
    try:
        global LOADED_FILE
        global LOADED_FILE_OPENED_FLAG
        
        loaded_file_name = os.path.basename(LOADED_FILE.name)
        bd_logger("Closing file... " + loaded_file_name) 
        sys.stdout.flush()
        
        LOADED_FILE.close()
        LOADED_FILE_OPENED_FLAG = False 
        in_menu.entryconfig(1, state="disabled")
        
        in_file_label.config(text="Loaded file: None")
        
        bd_logger("File " + loaded_file_name + " has been closed.") 
        sys.stdout.flush()      
        return
    
    except Exception as e:
        bd_logger("Error while closing file...")
        traceback.print_exc()
        sys.stdout.flush()
        return       
    
 
def change_canvas_width(in_w_label, in_canvas, in_canvas_settings, step):
    temp_width = in_canvas_settings[2] + step
    if (temp_width > in_canvas_settings[4]):  # new_width > max_width
        return    
    
    in_canvas_settings[2] = in_canvas_settings[2] + step
    in_canvas.place(x= in_canvas_settings[0], y= in_canvas_settings[1], width=in_canvas_settings[2], height=in_canvas_settings[3])  
    in_w_label.config(text="Canvas width: " + str(in_canvas_settings[2]) )
 
    
def change_canvas_height(in_h_label, in_canvas, in_canvas_settings, step):
    temp_height = in_canvas_settings[3] + step
    if (temp_height > in_canvas_settings[5]):  # new_height > max_height
        return    
    
    in_canvas_settings[3] = in_canvas_settings[3] + step
    in_canvas.place(x= in_canvas_settings[0], y= in_canvas_settings[1], width=in_canvas_settings[2], height=in_canvas_settings[3])   
    in_h_label.config(text="Canvas height: " + str(in_canvas_settings[3]) )
 
    
   
   
   
   
    
#main()




#main window
root = tk.Tk()
my_gui = BDTexView(root)
center_tk_window.center_on_screen(root)
root.mainloop()