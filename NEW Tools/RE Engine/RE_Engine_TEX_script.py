from inc_noesis import *

# RE Engine Noesis script
# Created by Bartlomiej Duda (Ikskoks)
# License: GPL-3.0 License


# Ver    Date        Author                             Comment
# v1.0   09.04.2024  Bartlomiej Duda                    -
# v1.1   10.04.2024  Bartlomiej Duda                    Add img type 10 support


# supported versions:
# v35 - Resident Evil 7 Biohazard (PC/Steam) (*.35)


# fmt: off
debug_mode_enabled = False


def registerNoesisTypes():
    handle = noesis.register("RE ENGINE TEX FILES", ".35;.tex")
    noesis.setHandlerTypeCheck(handle, image_check_type)
    noesis.setHandlerLoadRGBA(handle, image_load)


    if debug_mode_enabled:
        noesis.logPopup()
    return 1


def image_check_type(file_data):
    bs = NoeBitStream(file_data)
    signature = bs.readBytes(4).decode("UTF8")
    if (signature != "TEX\x00"):
        return 0
    return 1




def image_load(image_file_data, tex_list):

    bs = NoeBitStream(image_file_data)
    base_name = rapi.getInputName().split('\\')[-1].split('.')[0]
    print("base_name: ", base_name)

    # header parsing
    signature = bs.readUInt()  # TEX\x00
    version = bs.readUInt()  # e.g. 35
    if version != 35:
        noesis.messagePrompt("Version " + str(version) + " not supported! Exiting!")
        return 0
    img_width = bs.readUShort()
    img_height = bs.readUShort()
    unknown1 = bs.readUByte()
    unknown2 = bs.readUByte()
    number_of_images = bs.readUByte()
    one_image_mip_header_size = bs.readUByte()
    image_type = bs.readUInt()  # e.g. 95
    unknown3 = bs.readInt()  # -1
    unknown4 = bs.readUInt()
    flags = bs.readUInt()
    unknown5_1 = bs.readUInt()
    unknown5_2 = bs.readUInt()
    number_of_mipmaps = int(one_image_mip_header_size / 16)
    
    
    # mipmaps headers parsing
    images_list = []
    for i in range(number_of_images):
        mipmaps_list = []
        for j in range(number_of_mipmaps):
            image_data_offset = noeUnpack("<Q", bs.readBytes(8))[0]
            pitch = bs.readUInt()
            image_data_size = bs.readUInt()
            
            image_header = {
                "image_offset": image_data_offset,
                "image_size": image_data_size
            }
            mipmaps_list.append(image_header)
        images_list.append(mipmaps_list)
    
    

    # image data decoding
    for k in range(number_of_images):
        image_header_data = images_list[k][0]  # get only first mipmap
        
        out_image_offset = image_header_data.get("image_offset")
        out_image_size = image_header_data.get("image_size")
        
        bs.seek(out_image_offset)
        pixel_data = bs.readBytes(out_image_size)
        
        print("Decoding image " + str(k) + "..." + " img_offset: " + str(out_image_offset) + " img_size: " + str(out_image_size) + " img_width: " + str(img_width) + " img_height: " + str(img_height) + " img_type: " + str(image_type))
        
        if image_type == 10:
            pixel_data = rapi.imageDecodeRaw(pixel_data, img_width, img_height, "R16G16B16A16_FLOAT")
        elif image_type in (95, 96):
            pixel_data = rapi.imageDecodeDXT(pixel_data, img_width, img_height, noesis.FOURCC_BC6H)
        elif image_type in (98, 99):
            pixel_data = rapi.imageDecodeDXT(pixel_data, img_width, img_height, noesis.FOURCC_BC7)
        else:
            noesis.messagePrompt("Image type " + str(image_type) + " not supported! Exiting!")
            return 0
            
        texture_format = noesis.NOESISTEX_RGBA32
        texture_name = "%s_%d" % (base_name, k)
        tex_list.append(NoeTexture(texture_name, img_width, img_height, pixel_data, texture_format))
        
    print("\n")
    return 1
