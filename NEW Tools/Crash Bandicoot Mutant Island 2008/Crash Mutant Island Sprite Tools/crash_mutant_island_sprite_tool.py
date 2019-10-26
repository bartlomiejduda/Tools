# -*- coding: utf-8 -*-

# Tested on Python 3.7.3
# This tool should be used with Crash Mutant Island 2008 Java game

# Ver    Date        Name
# v1.0   20.10.2019  Bartlomiej Duda
# v1.1   26.10.2019  Bartlomiej Duda


VERSION_NUM = "v1.1"


import os
import sys
import struct
import traceback
from PIL import Image



def read_sprite(p_input_spritefile_path):
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
            sGlobalImagesInfos_ = sprite_file.read(8)
            out_file.write(sGlobalImagesInfos_)
            out_file.write(b"IKS")
    
    
    curr_offset = sprite_file.tell()
    print( " curr_offset_END: " + str(curr_offset) )        
    #animation data read
    byte7 = struct.unpack('>B', sprite_file.read(1))[0]
    print( "byte7: " + str(byte7)  )
    #for i in range(byte7):
        #array = sprite_file.read(4)
        #byte8 = struct.unpack('>B', sprite_file.read(1))[0]
        #array2 = sprite_file.read(byte8)
        #byte9 = struct.unpack('>B', sprite_file.read(1))[0]
        #image_data = sprite_file.read(4*byte8 + 1)
        #curr_offset = sprite_file.tell()
        #print( str(i+1) + ") " + "curr_offset: " + str(curr_offset) )
    
    sprite_file.close()
    out_file.close()
    
    #im_file = open('test.bin', 'rb')
    #im_data = im_file.read()
    #im_file.close()
    #image = Image.frombytes('1', (8,70), im_data, 'raw')
    #image.show()
    
    print ("Ending Crash Java sprite read...")
    
    

input_spritefile_path = "C:\\Users\\Adam\\Desktop\\Sprites_nb_5"
read_sprite(input_spritefile_path)