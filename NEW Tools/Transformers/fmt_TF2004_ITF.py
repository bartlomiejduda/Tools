# Transformers 2004 (PS2) ITF Texture Noesis plugin
# Written by flarespire
# 4 bit to 8 bit conversion & 8BPP ITF Support by Edness.
# Updated/Fixed by Bartlomiej Duda (Ikskoks)

from inc_noesis import *

# fmt: off
debug_mode_enabled = True

def registerNoesisTypes():
    handle = noesis.register("Transformers 2004 PS2 ITF Texture", ".ITF")
    noesis.setHandlerTypeCheck(handle, noepyCheckType)
    noesis.setHandlerLoadRGBA(handle, noepyLoadRGBA)
    if debug_mode_enabled:
        noesis.logPopup()
    return 1

def noepyCheckType(data):
    bs = NoeBitStream(data)
    signature = bs.readBytes(4).decode("ASCII")
    if signature != "FORM":
        return 0
    return 1
    
def noepyLoadRGBA(data, tex_list):
    bs = NoeBitStream(data)
    base_name = rapi.getInputName().split('\\')[-1].split('.')[0]
    bs.seek(20, NOESEEK_ABS)  # go to PS2 chunk
    chunk_signature = bs.readBytes(3)
    chunk_type = bs.readUByte()
    unk1 = bs.readUInt()  # bpp?
    img_width = bs.readUInt()
    img_height = bs.readUInt()
    unk2 = bs.readUInt()  # palette type?
    number_of_pals = bs.readUInt()
    bs.readBytes(8)  # read nulls
    
    bs.readBytes(4)  # read TXTR signature
    bs.readBytes(4)  # read chunk size
    
    
    print("DEBUG chunk_type: " + str(chunk_type))
    print("DEBUG unk1: " + str(unk1))
    print("DEBUG unk2: " + str(unk2))
    print("DEBUG number_of_pals: " + str(number_of_pals))
    print("\n")
    
    
    
    # decoding logic
    bits_per_pixel = 0
    number_of_palettes = 0
    pixel_size = 0
    palette_size = 0
    pixel_data_conv = b''
    
    
    if number_of_pals > 10:
        number_of_pals = 1  # workaround...
    
    
    if chunk_type == 2:  # 32-bit RGBA8888
        bits_per_pixel = 8
        pixel_size = (img_width * img_height) * 4
    elif chunk_type == 7:  # 16-bit RGB5551 (not swizzled)
        bits_per_pixel = 8
        pixel_size = (img_width * img_height) * 2
    elif chunk_type == 10: # 4-bit RGBA8888 PAL (not swizzled)
        if number_of_pals == 0:
            number_of_pals = 1
        number_of_palettes = number_of_pals
        palette_size = 64
        bits_per_pixel = 4
        pixel_size = (img_width * img_height) // 2
    elif chunk_type == 11:  # 8-bit RGBA8888 PAL (not swizzled)
        number_of_palettes = 1
        palette_size = 1024
        bits_per_pixel = 8
        pixel_size = img_width * img_height
    elif chunk_type == 138:  # 4-bit RGBA8888 PAL + PS2 SWIZZLE
        if number_of_pals == 0:
            number_of_pals = 1
        number_of_palettes = number_of_pals
        palette_size = 64
        bits_per_pixel = 8
        pixel_size = (img_width * img_height) // 2
    elif chunk_type == 139:  # 8-bit RGBA8888 PAL + PS2 SWIZZLE
        if number_of_pals == 0:
            number_of_pals = 1
        number_of_palettes = number_of_pals
        palette_size = 1024
        bits_per_pixel = 8
        pixel_size = (img_width * img_height)
    else:
        message = "Chunk type " + str(chunk_type) + " is not supported!"
        noesis.messagePrompt(message)
        return 0
    
    
    
    palettes_list = []
    palettes_offsets_list = []
    for i in range(number_of_palettes):
        palettes_offsets_list.append(bs.tell())
        palette_data = bs.readBytes(palette_size)
        palettes_list.append(palette_data)
    
    image_data_offset = bs.tell()
    pixel_data = bs.readBytes(pixel_size)
    
    
    # 4bpp->8bpp conversion
    if chunk_type == 138:  
        pixel_data_conv = []  
        for byte in pixel_data:
            pixel_data_conv.extend((byte & 0xF, byte >> 4))
        pixel_data_conv = bytearray(pixel_data_conv)
        pixel_data = pixel_data_conv
    
    
    number_of_images = 1
    if number_of_palettes > 1:
        number_of_images = number_of_palettes
    
    for i in range(number_of_images):
        print("chunk_type: " + str(chunk_type))
        print("img data offset: " + str(image_data_offset) + " \\ " + str(hex((image_data_offset))))
        print("img data size: " + str(pixel_size))
        print("number_of_palettes: " + str(number_of_palettes))
        if number_of_palettes > 0:
            print("pal data offset: " + str(palettes_offsets_list[i]) + " \\ " + str(hex((palettes_offsets_list[i]))))
            print("pal data size: " + str(palette_size))
        print("img_width: " + str(img_width))
        print("img_height: " + str(img_height))
        print("\n")
        
        if chunk_type == 2:
            pixel_data_conv = rapi.imageDecodeRaw(pixel_data, img_width, img_height, "R8 G8 B8 A8")  
        elif chunk_type == 7:       
            pixel_data_conv = rapi.imageDecodeRaw(pixel_data, img_width, img_height, "R5 G5 B5 A1") 
        elif chunk_type == 10:
            pixel_data_conv = rapi.imageDecodeRawPal(pixel_data, palettes_list[i], img_width, img_height, bits_per_pixel, "r8 g8 b8 a8")
        elif chunk_type == 11:
            pixel_data_conv = rapi.imageDecodeRawPal(pixel_data, palettes_list[i], img_width, img_height, bits_per_pixel, "r8 g8 b8 p8")
        elif chunk_type == 138:
            pixel_data_conv = rapi.imageUntwiddlePS2(pixel_data, img_width, img_height, bits_per_pixel)
            pixel_data_conv = rapi.imageDecodeRawPal(pixel_data_conv, palettes_list[i], img_width, img_height, bits_per_pixel, "r8 g8 b8 a8")
        elif chunk_type == 139:
            pixel_data_conv = rapi.imageUntwiddlePS2(pixel_data, img_width, img_height, bits_per_pixel)
            pixel_data_conv = rapi.imageDecodeRawPal(pixel_data_conv, palettes_list[i], img_width, img_height, bits_per_pixel, "r8 g8 b8 a8")
            
        texture_format = noesis.NOESISTEX_RGBA32
        texture_name = "%s_%d" % (base_name, i)
        tex_list.append(NoeTexture(texture_name, img_width, img_height, pixel_data_conv, texture_format))


    print("End of main.")
    return 0