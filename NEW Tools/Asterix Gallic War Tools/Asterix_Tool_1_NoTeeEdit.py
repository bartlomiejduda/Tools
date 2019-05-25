# -*- coding: utf-8 -*-


#This tool was made by Ikskoks for Xentax community.
#Please don't copy this tool to other forums and sites.

#If you like my tool, please consider visit my fanpage https://www.facebook.com/ikskoks/ and site http://ikskoks.pl/

#edited by NoTeefy for rubi :* (code is ugly as shit but it works...)


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


def unpack_DAT(dat_path, output_folder):
    fileSanitized = dat_path+'\\ASTERIX.DAT'
    file = open(fileSanitized, 'rb')
    (DAT_path, DAT_name) = os.path.split(dat_path)
    (DAT_short_name, temp2) = os.path.splitext(DAT_name)
    j = 0
    number_of_files = 3258
    print ('  » exporting ' + str(number_of_files) +' VAGs from\n   ' + fileSanitized + '\n  » into\n   ' + output_folder)
    for i in range(number_of_files):
        file_size = struct.unpack('<i', file.read(4))[0]
        file_data = file.read(file_size)
        file_name = "File" + str(j+1) + '.VAG'
        j += 1
        VAG_path = output_folder + '\\' + file_name
        VAG_file = open(VAG_path, 'wb+')
        VAG_file.write(file_data)
        VAG_file.close()

def pack_DAT(output_folder, dat_path):
    fileSanitized = dat_path+'\\ASTERIX.DAT'
    number_of_files = 3258
    j = 0
    print ('  » importing ' + str(number_of_files) +' VAGs from\n   ' + output_folder + '\n  » into\n   ' + fileSanitized)
    outputFile = open(fileSanitized, 'wb+')
    for i in range(number_of_files):
        curChunk = "File" + str(j+1) + '.VAG'
        curChunkSanitized = output_folder+'\\'+curChunk
        curChunkFile = open(curChunkSanitized, 'rb')
        curChunkSize = os.path.getsize(curChunkSanitized)
        curChunkData = curChunkFile.read(curChunkSize)
        j += 1
        if number_of_files == j:
            #last block, replace file_size by a little endian representation of 64 (dunno why...)
            outputFile.write(struct.pack('<i', 0x40004000))
        else:
            outputFile.write(struct.pack('<i', curChunkSize))
        outputFile.write(curChunkData)
        curChunkFile.close()
    outputFile.close()

def unpackTXT(vag_dir, output_dir):
    print ('  » exporting options.txt from\n   ' + output_dir + '\\File3258.VAG\n  » into\n   ' + vag_dir + '\\options.txt')
    outputFile = open(vag_dir+'\\options.txt', 'wb+')
    chunkFile = open(output_dir+'\\File3258.VAG', 'rb')
    chunkStartPoint = 0x13ED8 #address to start pointer at
    chunkMaxPoint = 0x286CF #address where the texts needs to stop to mitigate data overrides
    chunkMaxSize = chunkMaxPoint - chunkStartPoint
    currentNumBytes = 0
    print('maximum allowed text length: ' + str(chunkMaxSize))
    chunkFile.seek(chunkStartPoint)
    lastChunk = b''
    outputData = b''
    while True:
        chunkData = chunkFile.read(1) #read 8 bytes
        #print('chunkData equals: ' + chunkData.hex()) #debugging stuff
        if chunkData == b'\0' * 1: #skip of the last chunkData and break
            break #break out of while loop
        outputData += lastChunk
        currentNumBytes += 1
        #print('currently at: ' + str(currentNumBytes) + ' of allowed ' + str(chunkMaxSize))
        lastChunk = chunkData
        if currentNumBytes >= chunkMaxSize:
            break #break out of while loop
    chunkFile.close()
    outputLen = len(outputData)
    outputFile.write(outputData[0:outputLen-4])#get rid of ending
    outputFile.close()

def packTXT(chunk_dir, txt_dir):
    print ('  » importing options.txt from\n   ' + txt_dir + '\\options.txt\n  » into\n   ' + chunk_dir + '\\File3258.VAG')
    chunkFileSanitized = chunk_dir+'\\File3258.VAG'
    chunkFile = open(chunkFileSanitized, 'rb')
    chunkFileSize = os.path.getsize(chunkFileSanitized)
    chunkFileData = chunkFile.read(chunkFileSize)
    chunkFile.close()
    chunkStartPoint = 0x13ED8 #address to start pointer at
    chunkMaxPoint = 0x286CF #address where the texts needs to stop to mitigate data overrides
    txtFileSanitized = txt_dir+'\\options.txt'
    txtFile = open(txtFileSanitized, 'rb')
    txtSize = os.path.getsize(txtFileSanitized)
    maxSize = 83958
    if txtSize+1 > maxSize: #aborting if options.txt would cause an overflow
        print('  [!] File size equals ' + str(txtSize+1) + ' but the max. allowed amount is ' + str(maxSize))
        print('  [!] Aborting request (to prevent a .VAG overflow)')
        txtFile.close()
        return #return out of def
    chunkFileDataToWrite = chunkFileData[0:chunkStartPoint] #get everything before our own chunk
    chunkFileDataToWrite += txtFile.read(txtSize)
    chunkFileDataToWrite += bytearray.fromhex('0D0A0D0A1A') #append ending sequence again
    chunkFileDataSize = chunkStartPoint+txtSize+5
    chunkFileDataToWrite += chunkFileData[chunkFileDataSize:]
    chunkFile = open(chunkFileSanitized, 'wb+')
    chunkFile.write(chunkFileDataToWrite)
    chunkFile.close()
    txtFile.close()

#CHANGE TO YOUR OWN PATHS       
dat_path = 'C:\\Users\\Admin\\Documents\\Trad Asterix Gallic War\\FILES PSX' #path that leads to the extracted files from the image/disc
out_path = 'C:\\Users\\Admin\\Documents\\Trad Asterix Gallic War\\FILES PSX\\OUT' #output path for the extracted VAGs (just create an OUT folder in the directory that you provided above)

# uncomment whatever you need (packing/unpacking) and make sure your paths are correct!
#DAT UNPACK
#
#unpack_DAT(dat_path, out_path)
#
#DAT REPACK
#
pack_DAT(out_path, dat_path)
#
#TXT(options.txt) UNPACK
#
#unpackTXT(dat_path, out_path)
#
#TXT (options.txt) REPACK
#
#packTXT(out_path, dat_path)