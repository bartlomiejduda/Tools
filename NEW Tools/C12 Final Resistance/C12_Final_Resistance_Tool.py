# -*- coding: utf-8 -*-

# Tested on Python 3.7.3
# This tool should be used with C12 Final Resistance PAL SCES_03364

# Ver    Date        Name
# v1.0   29.06.2019  Bartlomiej Duda
# v1.1   11.07.2019  Bartlomiej Duda
# v1.2   12.07.2019  Bartlomiej Duda


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
from PIL import Image #need to install pillow for this!



def text_export(input_textfile_path, output_textfile_path):
    print ("Starting C12 text export...")
    
    str_arr = []
    ident_arr = []
    text_file = open(input_textfile_path, 'rt')
    out_file = open(output_textfile_path, 'wt+')
    
    for line in text_file:
        if line[0] == ';':
            continue
        
        ident_splitted = line.split(':')[:2]
        ident = ':'.join(ident_splitted) + ':'
        
        string = line.split(ident)[-1]
        #print (ident + string)
        str_arr.append(string)
        ident_arr.append(ident)
        
    for i in range(len(str_arr)):
        string = str_arr[i]
        if string[0] == '[':
            out_file.write(str_arr[i])
        else:
            out_file.write(ident_arr[i] + '=' + str_arr[i])
        
    text_file.close()
    out_file.close()
    
    print ("C12 text has been exported!")
    

def text_import(input_textfile_path, output_textfile_path):
    print ("Starting C12 text import...")
    
    ini_file = open(input_textfile_path, 'rt')
    txt_file = open(output_textfile_path, 'wb+')   
    
    lines_arr = []
    
    for line in ini_file:
        
        ident = line.split('=')[0]
        string = ''.join(line.split('=')[1:])
        
        #if ident == '23:1210:':
            #string = '=' + string
            
        #string = (
              #string.replace('Ż', '\xC1') #Ż 
                    #.replace('Ó', '\xD3') #Ó 
                    #.replace('Ł', '\xCA') #Ł 
                    #.replace('Ć', '\xD2') #Ć 
                    #.replace('Ę', '\xC9') #Ę 
                    #.replace('Ś', '\xDA') #Ś 
                    #.replace('Ą', '\xC0') #Ą 
                    #.replace('Ź', '\xC8') #Ź 
                    #.replace('Ń', '\xDB') #Ń 
                    
                    
                    #.replace('ż', '\xE1') #ż 
                    #.replace('ó', '\xF3') #ó 
                    #.replace('ł', '\xEA') #ł 
                    #.replace('ć', '\xF2') #ć  
                    #.replace('ę', '\xE9') #ę 
                    #.replace('ś', '\xFA') #ś 
                    #.replace('ą', '\xE0') #ą 
                    #.replace('ź', '\xE8') #ź 
                    #.replace('ń', '\XFB') #ń  

                    #)
            
        lines_arr.append(ident + string)    
        
    for line in lines_arr:
	
        line_bt = line.encode('utf-8')
        line_bt = (
	     line_bt.replace(b'\xC5\xBB', b'\xC1') #Ż 
	            .replace(b'\xC3\x93', b'\xD3') #Ó 
	            .replace(b'\xC5\x81', b'\xCA') #Ł 
	            .replace(b'\xC4\x86', b'\xD2') #Ć 
	            .replace(b'\xC4\x98', b'\xC9') #Ę 
	            .replace(b'\xC5\x9A', b'\xDA') #Ś 
	            .replace(b'\xC4\x84', b'\xC0') #Ą 
	            .replace(b'\xC5\xB9', b'\xC8') #Ź 
	            .replace(b'\xC5\x83', b'\xDB') #Ń 
	            
	            
	            .replace(b'\xC5\xBC', b'\xE1') #ż 
	            .replace(b'\xC3\xB3', b'\xF3') #ó 
	            .replace(b'\xC5\x82', b'\xEA') #ł 
	            .replace(b'\xC4\x87', b'\xF2') #ć  
	            .replace(b'\xC4\x99', b'\xE9') #ę 
	            .replace(b'\xC5\x9B', b'\xFA') #ś 
	            .replace(b'\xC4\x85', b'\xE0') #ą 
	            .replace(b'\xC5\xBA', b'\xE8') #ź 
	            .replace(b'\xC5\x84', b'\xFB') #ń  
	            
	            .replace(b'\x5B\x53\x74\x72\x69\x6E\x67\x54\x61\x62\x6C\x65\x5D\x0A', b'\x5B\x53\x74\x72\x69\x6E\x67\x54\x61\x62\x6C\x65\x5D\x0D\x0A') #[StringTable]

	            )	
        txt_file.write(line_bt)
        
        
    ini_file.close()
    txt_file.close()
    print('C12 text has been imported!')



def text_out(input_MWD_file, output_txt_file, text_start_offset, text_end_offset):
    print ("Starting C12 text out...")
    
    MWD_file = open(input_MWD_file, 'rb')
    txt_file = open(output_txt_file, 'wb+')   
    
    text_len = text_end_offset - text_start_offset
    MWD_file.seek(text_start_offset)
    text_data = MWD_file.read(text_len)
    txt_file.write(text_data)
    
    MWD_file.close()
    txt_file.close()
    print("C12 text out has been finished.")
    
    
def text_in(input_MWD_file, input_txt_file, text_start_offset, text_end_offset):
    print ("Starting C12 text in...")
    
    MWD_file = open(input_MWD_file, 'rb')
    txt_file = open(input_txt_file, 'rb') 
    MWD_file_new = open(input_MWD_file + '_NEW', 'wb+')
    
    
    MWD_txt_len = text_end_offset - text_start_offset
    txt_len = os.stat(input_txt_file).st_size
    padding_flag = -1
    
    if txt_len > MWD_txt_len:
        print("ERROR 01! TXT LENGTH IS BIGGER THAN MWD TXT LENGTH!")
        print("TXT file length is " + str(txt_len) + " and allowed text length is " + str(MWD_txt_len) + ". I'm aborting!")
        MWD_file.close()
        txt_file.close()
        MWD_file_new.close()        
        return
    elif txt_len < MWD_txt_len:
        print("TXT length is shorter than MWD txt length. I'm using padding to fill the gap.")
        padding_flag = 1
    else:
        print("TXT length is OK.")
        
    
    data1 = MWD_file.read(text_start_offset)
    MWD_file.seek(text_end_offset)
    data2 = MWD_file.read()
    
    MWD_file_new.write(data1)
    txt_data = txt_file.read()
    MWD_file_new.write(txt_data)
    
    if padding_flag == 1:
        padding_len = MWD_txt_len - txt_len
        for i in range(padding_len):
            MWD_file_new.write(b'\x00')
            
    MWD_file_new.write(data2)
    
    MWD_file.close()
    txt_file.close()
    MWD_file_new.close()
    print("C12 text in has been finished.")    
    

def from16(p):
	return ((p & 0x1f) << 3, (p >> 2) & 0xf8, (p >> 7) & 0xf8, p >> 15)
    
def texture_export(input_MWD_file, output_folder): #modified code for texture export published by torn338 on MediEvil Boards  (still not fully working)
    MWD_file = open(input_MWD_file, 'rb')
    d = MWD_file.read()
    
    i = -1
    while True:
	    i = d.find(b"2GRV", i + 1)
	    if i == -1:
		    break
    
	    si = i
	    print ("graphics chunk @ %#x" % si)
    
	    i += 4
	    num_img, off_img, num_stuff, off_stuff = struct.unpack("<4I", d[i:i + 4 * 4])
    
	    print ("\t%d images @ offset %#x" % (num_img, off_img))
    
	    i += 4 * 4
    
	    unk_x, unk_y, width, height, offset, whatever1, clut, texpage, whatever2 = struct.unpack("<2H2HII2HI", d[i+(num_img-1)*24:i+num_img*24])
	    pal_off = si + offset + width * 2 * height
	    print ("\tpal off @ %#x" % pal_off)
    
	    for n in range(num_img):
		    unk_x, unk_y, width, height, offset, whatever1, texpage, clut, whatever2, whatever3 = struct.unpack("<2H2HIHHHHI", d[i:i+24])
		    mode = (texpage >> 7) & 3
    
		    if mode == 0:
			    assert clut
			    width *= 4
		    elif mode == 1:
			    assert clut
			    width *= 2
		    elif mode == 2:
			    assert not clut
		    else:
			    assert False, "weird mode"
    
		    #print ("\t\timage @ offset %#x: %dx%dpx, mode %d, VRAM pos? (%d, %d), CLUT? %#x, texpage? %#x, extra %08x:%08x" % (offset, width, height, mode, unk_x, unk_y, clut, texpage, whatever1, whatever2))
    
		    i += 24
    
		    im = Image.new("RGBA", (width, height))
		    imd = im.load()
		    pn = 0
		    soffset = si + offset
		    for y in range(height):
			    for x in range(width):
				    if mode == 0:
					    pi = pal_off + ((d[soffset + (pn >> 1)] >> ((x & 1) * 4)) & 0xf) * 2
				    elif mode == 1:
					    pi = pal_off + d[soffset + pn] * 2
				    elif mode == 2:
					    pi = soffset + (pn << 1)
    
				    r, g, b, a = from16(struct.unpack("<H", d[pi:pi + 2])[0])
				    imd[x, y] = (r, g, b)
    
				    pn += 1
    
		    im.save(p_output_folder + "img-%d-%03d.png" % (si, n))  
		    
    print("Texture export has been finished.")

#TEXT EXPORT (converts TXT to INI)
#p_input_textfile_path = 'C:\\Users\\Arek\\Desktop\\C12_FILES\\out_PAL.txt'   
#p_output_textfile_path = 'C:\\Users\\Arek\\Desktop\\C12_FILES\\out_PAL.ini'  #put here output ini filepath
#text_export(p_input_textfile_path, p_output_textfile_path)



#TEXT IMPORT (converts INI to TXT)
#p_input_INI_file = 'C:\\Users\\Arek\\Spolszczenia\\C12_Final_Resistance_OmegaT\\target\\out_PAL.ini'  
#p_output_TXT_file = 'C:\\Users\\Arek\\Spolszczenia\\C12_Final_Resistance_OmegaT\\target\\out_PAL.txt'
#text_import(p_input_INI_file, p_output_TXT_file)


#TEXT OUT (copies text from PROJFILE.MWD to TXT file)
#p_input_MWD_file = 'C:\\Users\\Arek\\Desktop\\C12_FILES\\PROJFILE.MWD'
#p_output_txt_file = 'C:\\Users\\Arek\\Desktop\\C12_FILES\\out.txt'
#p_text_start_offset = 489472 
#p_text_end_offset = 555657
#text_out(p_input_MWD_file, p_output_txt_file, p_text_start_offset, p_text_end_offset)


#TEXT IN (copies text from TXT file to PROJFILE.MWD)
p_input_MWD_file = 'C:\\Users\\Arek\\Desktop\\C12_FILES\\PROJFILE.MWD'
p_input_txt_file = 'C:\\Users\\Arek\\Spolszczenia\\C12_Final_Resistance_OmegaT\\target\\out_PAL.txt'
p_text_start_offset = 489472 
p_text_end_offset = 555657
text_in(p_input_MWD_file, p_input_txt_file, p_text_start_offset, p_text_end_offset)


#TEXTURE EXPORT (exports textures from PROJFILE.MWD)
#p_input_MWD_file = 'C:\\Users\\Arek\\Desktop\\C12_FILES\\PROJFILE.MWD'
#p_output_folder = 'C:\\Users\\Arek\\Desktop\\C12_FILES\\TEXTURE_OUT\\'
#texture_export(p_input_MWD_file, p_output_folder)