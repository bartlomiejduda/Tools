from inc_noesis import *

# Based on tex_JB007FromRussiawithLove_PSP_tga.py
# Script updated for Miami Vice by Bartlomiej Duda (Ikskoks)

def registerNoesisTypes():
    handle = noesis.register("Miami Vice: The Game (PSP)", ".tga")
    noesis.setHandlerTypeCheck(handle, noepyCheckType)
    noesis.setHandlerLoadRGBA(handle, noepyLoadRGBA)
    #noesis.logPopup()
    return 1

def noepyCheckType(data):
    return 1

def noepyLoadRGBA(data, texList):
    bs = NoeBitStream(data)
    imgWidth = bs.readUShort()
    imgHeight = bs.readUShort()
    unk = bs.readShort()
    unk = bs.readShort()
    data = bs.readBytes(imgWidth * imgHeight)
    
    
    total_file_size = bs.getSize()
    palette_offset = total_file_size - 1024
    bs.seek(palette_offset, NOESEEK_ABS)
    
    
    palette = bs.readBytes(1024)
    data = rapi.imageUntwiddlePSP(data, imgWidth, imgHeight, 8)
    data = rapi.imageDecodeRawPal(data, palette, imgWidth, imgHeight, 8, "r8 g8 b8 p8")
    texList.append(NoeTexture(rapi.getInputName(), imgWidth, imgHeight, data, noesis.NOESISTEX_RGBA32))
    return 1
    