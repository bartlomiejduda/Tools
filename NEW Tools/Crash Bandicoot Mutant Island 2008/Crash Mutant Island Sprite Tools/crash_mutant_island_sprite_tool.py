# -*- coding: utf-8 -*-

# Tested on Python 3.7.3
# This tool should be used with Crash Mutant Island 2008 Java game

# Ver    Date        Name
# v1.0   20.10.2019  Bartlomiej Duda


VERSION_NUM = "v1.0"


import os
import sys
import struct
import traceback



def read_sprite(p_input_spritefile_path):
    print ("Starting Crash Java sprite read...")
    sprite_file = open(p_input_spritefile_path, 'rb')
    
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
        byte6 = struct.unpack('>B', sprite_file.read(1))[0]
        for i in range(byte6):
            n = struct.unpack('>B', sprite_file.read(1))[0]
            sGlobalImagesInfos_ = sprite_file.read(8)
            
    #image data read
    byte7 = struct.unpack('>B', sprite_file.read(1))[0]
    print( "byte7: " + str(byte7)  )
    
    
    
    print ("Ending Crash Java sprite read...")
    
    

input_spritefile_path = "C:\\Users\\Adam\\Desktop\\Sprites_nb_5"
read_sprite(input_spritefile_path)