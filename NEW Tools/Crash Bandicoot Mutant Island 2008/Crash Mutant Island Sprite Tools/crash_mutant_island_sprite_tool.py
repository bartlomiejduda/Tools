# -*- coding: utf-8 -*-

# Tested on Python 3.7.3
# This tool should be used with Crash Mutant Island 2008 Java game

# Ver    Date        Name
# v1.0   20.10.2019  Bartlomiej Duda
# v1.1   26.10.2019  Bartlomiej Duda
# v1.2   26.10.2019  Bartlomiej Duda
# v1.3   27.10.2019  Bartlomiej Duda
# v1.4   03.02.2020  Bartlomiej Duda
# v1.5   04.02.2020  Bartlomiej Duda


VERSION_NUM = "v1.4"


import os
import sys
import struct
import traceback
from PIL import Image



def read_palettes(p_input_palette_filepath):
    print("Starting Crash Java palette read...")
    palette_file = open(p_input_palette_filepath, 'rb')
    
    num_of_palettes = struct.unpack('>B', palette_file.read(1))[0]
    palette_arr = []
    
    for i in range(num_of_palettes):
        palette_size = struct.unpack('>H', palette_file.read(2))[0]
        palette_block = palette_file.read(palette_size)
        palette_arr.append(palette_block)
        #print("Curr_offset: " + str(palette_file.tell())  )
        
    palette_file.close()    
    print("Ending Crash Java palette read...")
    
    
def read_styles(p_input_stylefile_filepath):
    print("Starting Crash Java style read...")
    style_file = open(p_input_stylefile_filepath, 'rb')
    
    num_of_styles = struct.unpack('>B', style_file.read(1))[0]
    style_list_arr = []

    for i in range(num_of_styles):
        style_arr = []
        read2_val = struct.unpack('>B', style_file.read(1))[0]
        for i in range(read2_val):
            style_size = struct.unpack('>B', style_file.read(1))[0]
            style_block = style_file.read(5 * style_size)
            style_arr.append(style_block)
            print("Curr_offset: " + str(style_file.tell())  )
        
    style_file.close()    
    print("Ending Crash Java style read...")    


#119
def read_graphics(p_input_graphicsfile_filepath):
    print("Starting Crash Java graphics read...")
    graphics_file = open(p_input_graphicsfile_filepath, 'rb')   
    num_of_graphics = struct.unpack('>B', graphics_file.read(1))[0]
    graphics_offsets_arr = []
    graphics_data_arr = []
    for i in range(num_of_graphics):
        gr_offset = struct.unpack('>i', graphics_file.read(4))[0]
        graphics_offsets_arr.append(gr_offset)
    for i in range(num_of_graphics):
        gr_size = struct.unpack('>H', graphics_file.read(2))[0]
        gr_block = graphics_file.read(gr_size)
        graphics_data_arr.append(gr_block)
        print("Curr_offset: " + str(graphics_file.tell())  )
        
    graphics_file.close()    
    print("Ending Crash Java graphics read...")        



def read_sprite(p_input_spritefile_path, p_output_folder):
    print ("Starting Crash Java sprite read...")
    sprite_file = open(p_input_spritefile_path, 'rb')
    
    out_file = open('test.bin', 'wb+')
    
    #header read
    magic = struct.unpack('>B', sprite_file.read(1))[0]
    byte2 = struct.unpack('>B', sprite_file.read(1))[0]
    byte3 = struct.unpack('>B', sprite_file.read(1))[0]
    byte4 = struct.unpack('>B', sprite_file.read(1))[0]
    byte5 = struct.unpack('>B', sprite_file.read(1))[0]
    
    print( "magic: " + str(magic) + '\n' +
           "byte2: " + str(byte2) + '\n' +
           "byte3: " + str(byte3) + '\n' +
           "byte4: " + str(byte4) + '\n' +
           "byte5: " + str(byte5) + '\n')
    
    #image info read       
    for i in range(byte4):
        curr_offset = sprite_file.tell()
        byte6 = struct.unpack('>B', sprite_file.read(1))[0]
        info1 = struct.unpack('>B', sprite_file.read(1))[0]
        print( "byte6: " + str(byte6) + " info1: " + str(info1) + " curr_offset: " + str(curr_offset) )
        for i in range(byte6):
            n = struct.unpack('>B', sprite_file.read(1))[0]
            #print("n: " + str(n) )
            #sGlobalImagesInfos_ = sprite_file.read(8)
            x_pos = struct.unpack('>H', sprite_file.read(2))[0]
            y_pos = struct.unpack('>H', sprite_file.read(2))[0]
            width = struct.unpack('>H', sprite_file.read(2))[0]
            height = struct.unpack('>H', sprite_file.read(2))[0]
            #out_file.write(sGlobalImagesInfos_)
            #out_file.write(b"IKS")
            print("n: " + str(n) + " x_pos: " + str(x_pos) + " y_pos: " + str(y_pos) + " width: " + str(width) + " height: " + str(height) )
    
    
    curr_offset = sprite_file.tell()
    print( " curr_offset_END: " + str(curr_offset) )   
    
    if not os.path.exists(p_output_folder):
        os.mkdir(p_output_folder)
    
    #animation data read
    byte7 = struct.unpack('>B', sprite_file.read(1))[0]
    print( "byte7: " + str(byte7)  )
    for i in range(byte7):
        #array = sprite_file.read(4)
        array = []
        array.append(struct.unpack('>B', sprite_file.read(1))[0])
        array.append(struct.unpack('>B', sprite_file.read(1))[0])
        array.append(struct.unpack('>B', sprite_file.read(1))[0])
        array.append(struct.unpack('>B', sprite_file.read(1))[0])
        
        byte8 = struct.unpack('>B', sprite_file.read(1))[0]
        array2 = sprite_file.read(byte8)
        byte9 = struct.unpack('>B', sprite_file.read(1))[0]
        im_data_all = b''
        for j in range(byte9):
            short1 = struct.unpack('>H', sprite_file.read(2))[0]
            n6 = 4 * byte8 + 1
            im_data_line = b''
            data_read_off_start = sprite_file.tell()
            for k in range(n6-1):
                im_data_byte = sprite_file.read(1)
                im_data_line += im_data_byte
            im_data_all += im_data_line
            curr_offset = sprite_file.tell()
            data_read_off_end = sprite_file.tell()
            #print( str(j+1) + ") " + "curr_offset_loop: " + str(curr_offset) + " n6: " + str(n6) + " short1: " + str(short1)  )
            print( str(j+1) + ") " + "off_start: " + str(data_read_off_start) + " off_end: " + str(data_read_off_end) )
        
        image = Image.frombytes('L', (1,1), im_data_all, 'raw')  
        im_save_path = p_output_folder + '\\' + str(i) + '.png'
        #print("im_save_path: " + im_save_path)
        image.save(im_save_path)
            
        curr_offset = sprite_file.tell()
        print( str(i+1) + ") " + "curr_offset: " + str(curr_offset) 
               + " a[0]: " + str(array[0]) 
               + " a[1]: " + str(array[1]) 
               + " a[2]: " + str(array[2]) 
               + " a[3]: " + str(array[3]) 
               + " byte8: " + str(byte8)
               + " byte9: " + str(byte9)
               
               )    #+ " len_data: " + str(sys.getsizeof(im_data_all)) )
    
    sprite_file.close()
    out_file.close()
    
    #im_file = open('test.bin', 'rb')
    #im_data = im_file.read()
    #im_file.close()
    #image = Image.frombytes('RGB', (12,12), im_data_all, 'raw')
    #image.show()
    
    print ("Ending Crash Java sprite read...")
    
    

#input_spritefile_path = "C:\\Users\\Adam\\Desktop\\Sprites_nb_5"
#output_folder = "C:\\Users\\Adam\\Desktop\\Sprites_nb_5_out"
#read_sprite(input_spritefile_path, output_folder)



#p_input_palette_filepath = "C:\\Users\\Arek\\Desktop\\Boards_Palettes.bin"
#read_palettes(p_input_palette_filepath)


#p_input_stylefile_filepath = "C:\\Users\\Arek\\Desktop\\Boards_Styles_Datas.bin"
#read_styles(p_input_stylefile_filepath)

p_input_graphicsfile_filepath = "C:\\Users\\Arek\\Desktop\\119"
read_graphics(p_input_graphicsfile_filepath)