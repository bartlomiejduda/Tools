from inc_noesis import *

# Storm Engine Noesis script
# Created by Bartlomiej Duda (Ikskoks)
# License: GPL-3.0 License


# Ver    Date        Author                             Comment
# v0.1   18.11.2023  Bartlomiej Duda                    -
# v0.2   21.11.2023  Bartlomiej Duda/BloodRaynare       -


# fmt: off
debug_mode_enabled = False


def registerNoesisTypes():
    handle = noesis.register("STORM ENGINE TX FILES", ".tx")
    noesis.setHandlerTypeCheck(handle, image_check_type)
    noesis.setHandlerLoadRGBA(handle, image_load)


    if debug_mode_enabled:
        noesis.logPopup()
    return 1


def image_check_type(file_data):
    return 1




def image_load(image_file_data, tex_list):

    bs = NoeBitStream(image_file_data)
    base_name = rapi.getInputName().split('\\')[-1].split('.')[0]
    print("base_name: ", base_name)
    i = 0

    # header parsing
    flags = bs.readUInt()
    img_width = bs.readUInt()
    img_height = bs.readUInt()
    number_of_mipmaps = bs.readUInt()
    tx_format = bs.readUInt()
    mip0_size = bs.readUInt()
    print("tx_format: " + str(tx_format))
    
    
    if tx_format == 21: # TXF_A8R8G8B8
        bytes_per_pixel = 4
        pixel_size = img_width * img_height * bytes_per_pixel
        pixel_data = bs.readBytes(pixel_size)
        pixel_data = rapi.imageDecodeRaw(pixel_data, img_width, img_height, "b8 g8 r8 a8")
        
    elif tx_format == 22: # TXF_X8R8G8B8
        bytes_per_pixel = 4
        pixel_size = img_width * img_height * bytes_per_pixel
        pixel_data = bs.readBytes(pixel_size)
        pixel_data = rapi.imageDecodeRaw(pixel_data, img_width, img_height, "b8 g8 r8 p8")
        
    elif tx_format == 23: # TXF_R5G6B5
        bytes_per_pixel = 2
        pixel_size = img_width * img_height * bytes_per_pixel
        pixel_data = bs.readBytes(pixel_size)
        pixel_data = rapi.imageDecodeRaw(pixel_data, img_width, img_height, "b5 g6 r5")
        
    elif tx_format == 25: # TXF_A1R5G5B5
        bytes_per_pixel = 2
        pixel_size = img_width * img_height * bytes_per_pixel
        pixel_data = bs.readBytes(pixel_size)
        pixel_data = rapi.imageDecodeRaw(pixel_data, img_width, img_height, "b5 g5 r5 a1")
    
    elif tx_format == 26: # TXF_A4R4G4B4
        bytes_per_pixel = 2
        pixel_size = img_width * img_height * bytes_per_pixel
        pixel_data = bs.readBytes(pixel_size)
        pixel_data = rapi.imageDecodeRaw(pixel_data, img_width, img_height, "b4 g4 r4 a4")
        
    elif tx_format == 827611204:  # DXT1
        pixel_size = (img_width * img_height)
        if pixel_size >= len(image_file_data):
            pixel_size = len(image_file_data) - 24
        pixel_data = bs.readBytes(pixel_size)
        pixel_data = rapi.imageDecodeDXT(pixel_data, img_width, img_height, noesis.FOURCC_DXT1)
        
    elif tx_format == 844388420:  # DXT2
        pixel_size = (img_width * img_height)
        pixel_data = bs.readBytes(pixel_size)
        pixel_data = rapi.imageDecodeDXT(pixel_data, img_width, img_height, noesis.FOURCC_DXT2)
        
    elif tx_format == 861165636:  # DXT3
        pixel_size = (img_width * img_height)
        pixel_data = bs.readBytes(pixel_size)
        pixel_data = rapi.imageDecodeDXT(pixel_data, img_width, img_height, noesis.FOURCC_DXT3)
        
    elif tx_format == 877942852:  # DXT4
        pixel_size = (img_width * img_height)
        pixel_data = bs.readBytes(pixel_size)
        pixel_data = rapi.imageDecodeDXT(pixel_data, img_width, img_height, noesis.FOURCC_DXT4)
        
    elif tx_format == 894720068:  # DXT5
        pixel_size = (img_width * img_height)
        pixel_data = bs.readBytes(pixel_size)
        pixel_data = rapi.imageDecodeDXT(pixel_data, img_width, img_height, noesis.FOURCC_DXT5)
   
    else:
        message = "TX type " + str(tx_format) + " is not supported!"
        noesis.messagePrompt(message)
        return 0
        
    texture_format = noesis.NOESISTEX_RGBA32
    texture_name = "%s_%d" % (base_name, i)
    tex_list.append(NoeTexture(texture_name, img_width, img_height, pixel_data, texture_format))
        
    print("\n")
    return 1
