# Script by Bartlomiej Duda (Ikskoks)
# Soulbringer .B16 / .BIN


# Ver    Date        Author               Comment
# v0.1   24.01.2022  Bartlomiej Duda      -


from inc_noesis import *
import noesis
import rapi

def registerNoesisTypes():
   handle = noesis.register("Soulbringer", ".b16")
   noesis.setHandlerTypeCheck(handle, texCheckType)
   noesis.setHandlerLoadRGBA(handle, texLoadRGBA_B16)
   noesis.setHandlerWriteRGBA(handle, texWriteRGBA_B16)
   
   handle2 = noesis.register("Soulbringer", ".bin")
   noesis.setHandlerTypeCheck(handle2, texCheckType)
   noesis.setHandlerLoadRGBA(handle2, texLoadRGBA_BIN)
   noesis.setHandlerWriteRGBA(handle2, texWriteRGB_BIN)
   return 1

def texCheckType(data):
   return 1

def texLoadRGBA_B16(data, texList):
   tex = SOUL_Texture(NoeBitStream(data))
   texList.append(tex.parseTexture_B16())
   return 1
   
def texLoadRGBA_BIN(data, texList):
   tex = SOUL_Texture(NoeBitStream(data))
   texList.append(tex.parseTexture_BIN())
   return 1

class SOUL_Texture:

   def __init__(self, reader):
      self.reader = reader

   def parseTexture_B16(self):
      texWidth   = 256
      texHeight  = 256

      pixMap = self.reader.readBytes(texWidth * texHeight * 2)
      pixData = rapi.imageDecodeRaw(pixMap, texWidth, texHeight, "b5 g5 r5 a1")

      return NoeTexture("b16", texWidth, texHeight, pixData, noesis.NOESISTEX_RGBA32)
      
   def parseTexture_BIN(self):
      texWidth   = 256
      texHeight  = 256

      pixMap = self.reader.readBytes(texWidth * texHeight)
      pixData = rapi.imageDecodeRaw(pixMap, texWidth, texHeight, "r3 g3 b2")

      return NoeTexture("bin", texWidth, texHeight, pixData, noesis.NOESISTEX_RGBA32)
   
def texWriteRGBA_B16(data, width, height, filewriter):
     
      imageData = rapi.imageEncodeRaw(data, width, height, "b5 g5 r5 a1")
      filewriter.writeBytes(imageData)
      return 1
      
def texWriteRGB_BIN(data, width, height, filewriter):
     
      imageData = rapi.imageEncodeRaw(data, width, height, "r3 g3 b2")
      filewriter.writeBytes(imageData)
      return 1
      