"""
Copyright © 2024  Bartłomiej Duda
License: GPL-3.0 License
"""
import os
import sys
from typing import Optional

from reversebox.common.logger import get_logger
from reversebox.image.image_decoder import ImageDecoder
from reversebox.image.image_encoder import ImageEncoder
from reversebox.image.image_formats import ImageFormats
from reversebox.image.pillow_wrapper import PillowWrapper
from reversebox.image.swizzling.swizzle_psp import unswizzle_psp, swizzle_psp
from reversebox.io_files.file_handler import FileHandler

logger = get_logger(__name__)


def get_file_data(raw_file_path: str) -> bytes:
    logger.info(f"get_file_data start, file_name={raw_file_path}")
    raw_file = FileHandler(raw_file_path, "rb", "little")
    raw_file_data: bytes = raw_file.read_whole_file_content()
    return raw_file_data


def decode_raw(raw_file_data: bytes, decoder_type: str, image_width: int, image_height: int, image_format: ImageFormats, image_endianess: str = "little", swizzle_type: Optional[str] = None, image_bpp: Optional[int] = None, show_preview: bool = True) -> bytes:
    logger.info(f"decode_raw start")

    image_decoder = ImageDecoder()
    wrapper = PillowWrapper()

    if swizzle_type == "PSP":
        raw_file_data = unswizzle_psp(
                        raw_file_data, image_width, image_height, image_bpp
                    )

    if decoder_type == "generic":
        decoded_image_data: bytes = image_decoder.decode_image(
            raw_file_data, image_width, image_height, image_format, image_endianess
        )
    elif decoder_type == "yuv":
        decoded_image_data: bytes = image_decoder.decode_yuv_image(
            raw_file_data, image_width, image_height, image_format
        )
    else:
        raise Exception(f"Decoder type not supported! Decoder_type: {decoder_type}")

    pil_image = wrapper.get_pillow_image_from_rgba8888_data(decoded_image_data, image_width, image_height)
    if show_preview:
        pil_image.show()

    logger.info("decode_raw end")
    return decoded_image_data


def encode_raw(raw_file_data: bytes, encoder_type: str, image_width: int, image_height: int, image_format: ImageFormats, image_endianess: str = "little", swizzle_type: Optional[str] = None, image_bpp: Optional[int] = None) -> bytes:
    logger.info(f"encode_raw start")

    image_encoder = ImageEncoder()

    if encoder_type == "generic":
        encoded_image_data: bytes = image_encoder.encode_image(
            raw_file_data, image_width, image_height, image_format, image_endianess
        )
    else:
        raise Exception(f"Encoder type not supported! Encoder_type: {encoder_type}")

    if swizzle_type == "PSP":
        encoded_image_data = swizzle_psp(encoded_image_data, image_width, image_height, image_bpp)

    logger.info("encode_raw end")
    return encoded_image_data


def main():
    """
    Main function of this program.
    """
    logger.info("Starting main...")
    path_base: str = os.environ["IMG_PATH_BASE"]

    # decode_raw(os.path.join(path_base, "RGB\\rgb565_380x504.bin"), "generic", 380, 504, ImageFormats.RGB565)
    # decode_raw(os.path.join(path_base, "RGB\\Lena_512x512_RGB_888"), "generic", 512, 512, ImageFormats.RGB888)
    # decode_raw(os.path.join(path_base, "RGB\\rgb888_256x128.bin"), "generic", 256, 128, ImageFormats.RGB888)
    # decode_raw(os.path.join(path_base, "RGB\\bgr888_256x128.bin"), "generic", 256, 128, ImageFormats.BGR888)
    # decode_raw(os.path.join(path_base, "RGB\\PIX_FMT_RGB8.bin"), "generic", 256, 128, ImageFormats.RGB332)
    # decode_raw(os.path.join(path_base, "PIX_FMT_BGR8.bin"), "generic", 256, 128, ImageFormats.BGR332)
    # decode_raw(os.path.join(path_base, "PIX_FMT_RGBA.bin"), "generic", 256, 128, ImageFormats.RGBA8888)
    # decode_raw(os.path.join(path_base, "PIX_FMT_BGRA.bin"), "generic", 256, 128, ImageFormats.BGRA8888)
    # decode_raw(os.path.join(path_base, "RGB\\PIX_FMT_ARGB.bin"), "generic", 256, 128, ImageFormats.ARGB8888)
    # decode_raw(os.path.join(path_base, "PIX_FMT_ABGR.bin"), "generic", 256, 128, ImageFormats.ABGR8888)
    # decode_raw(os.path.join(path_base, "PIX_FMT_GRAY8.bin"), "generic", 256, 128, ImageFormats.GRAY8)
    # decode_raw(os.path.join(path_base, "PIX_FMT_YUYV422.bin"), "yuv", 256, 128, ImageFormats.YUY2)
    # decode_raw(os.path.join(path_base, "YUV\\PIX_FMT_NV12.bin"), "yuv", 256, 128, ImageFormats.NV12)
    # decode_raw(os.path.join(path_base, "PIX_FMT_NV21.bin"), "yuv", 256, 128, ImageFormats.NV21)
    # decode_raw(os.path.join(path_base, "PIX_FMT_UYVY422.bin"), "yuv", 256, 128, ImageFormats.UYVY)
    # decode_raw(os.path.join(path_base, "PIX_FMT_YUV444P.bin"), "yuv", 256, 128, ImageFormats.YUV444P)
    # decode_raw(os.path.join(path_base, "PIX_FMT_YUV410P.bin"), "yuv", 256, 128, ImageFormats.YUV410P)
    # decode_raw(os.path.join(path_base, "PIX_FMT_YUV420P.bin"), "yuv", 256, 128, ImageFormats.YUV420P)
    # decode_raw(os.path.join(path_base, "PIX_FMT_YUV422P.bin"), "yuv", 256, 128, ImageFormats.YUV422P)
    # decode_raw(os.path.join(path_base, "PIX_FMT_YUV411P.bin"), "yuv", 256, 128, ImageFormats.YUV411P)
    # decode_raw(os.path.join(path_base, "PIX_FMT_YUV411P.bin"), "yuv", 256, 128, ImageFormats.UYYVYY411)
    # decode_raw(os.path.join(path_base, "tulips_yuyv422_prog_packed_qcif.yuv"), "yuv", 176, 144, ImageFormats.YUY2)
    # decode_raw(os.path.join(path_base, "PIX_FMT_YUV440P.bin"), "yuv", 256, 128, ImageFormats.YUV440P)
    # decode_raw(os.path.join(path_base, "PIX_FMT_YUVA420P.bin"), "yuv", 256, 128, ImageFormats.YUVA420P)
    # decode_raw(os.path.join(path_base, "PIX_FMT_GRAY8A.bin"), "generic", 256, 128, ImageFormats.GRAY8A)
    # decode_raw(os.path.join(path_base, "PIX_FMT_GRAY16LE.bin"), "generic", 256, 128, ImageFormats.GRAY16, "little")
    # decode_raw(os.path.join(path_base, "PIX_FMT_GRAY16BE.bin"), "generic", 256, 128, ImageFormats.GRAY16, "big")
    # decode_raw(os.path.join(path_base, "PIX_FMT_0RGB.bin"), "generic", 256, 128, ImageFormats.XRGB8888, "big")
    # decode_raw(os.path.join(path_base, "PIX_FMT_RGB0.bin"), "generic", 256, 128, ImageFormats.RGBX8888, "big")
    # decode_raw(os.path.join(path_base, "PIX_FMT_0BGR.bin"), "generic", 256, 128, ImageFormats.XBGR8888, "big")
    # decode_raw(os.path.join(path_base, "PIX_FMT_BGR0.bin"), "generic", 256, 128, ImageFormats.BGRX8888, "big")
    # decode_raw(os.path.join(path_base, "PIX_FMT_RGB4_BYTE.bin"), "generic", 256, 128, ImageFormats.RGB121_BYTE)
    # decode_raw(os.path.join(path_base, "PIX_FMT_RGB4_BYTE.bin"), "generic", 256, 128, ImageFormats.RGB121_BYTE, "little")
    # decode_raw(os.path.join(path_base, "PIX_FMT_RGB565LE.bin"), "generic", 256, 128, ImageFormats.RGB565, "little")
    # decode_raw(os.path.join(path_base, "PIX_FMT_RGB565BE.bin"), "generic", 256, 128, ImageFormats.RGB565, "big")
    # decode_raw(os.path.join(path_base, "PIX_FMT_BGR565LE.bin"), "generic", 256, 128, ImageFormats.BGR565, "little")
    # decode_raw(os.path.join(path_base, "PIX_FMT_BGR565BE.bin"), "generic", 256, 128, ImageFormats.BGR565, "big")
    # decode_raw(os.path.join(path_base, "PIX_FMT_RGB555LE.bin"), "generic", 256, 128, ImageFormats.XRGB1555, "little")
    # decode_raw(os.path.join(path_base, "PIX_FMT_RGB555BE.bin"), "generic", 256, 128, ImageFormats.XRGB1555, "big")
    # decode_raw(os.path.join(path_base, "PIX_FMT_BGR555LE.bin"), "generic", 256, 128, ImageFormats.XBGR1555, "little")
    # decode_raw(os.path.join(path_base, "PIX_FMT_BGR555BE.bin"), "generic", 256, 128, ImageFormats.XBGR1555, "big")
    # decode_raw(os.path.join(path_base, "PIX_FMT_RGB444LE.bin"), "generic", 256, 128, ImageFormats.RGBX4444, "little")
    # decode_raw(os.path.join(path_base, "PIX_FMT_RGB444BE.bin"), "generic", 256, 128, ImageFormats.RGBX4444, "big")
    # decode_raw(os.path.join(path_base, "PIX_FMT_BGR444LE.bin"), "generic", 256, 128, ImageFormats.BGRX4444, "little")
    # decode_raw(os.path.join(path_base, "PIX_FMT_BGR444BE.bin"), "generic", 256, 128, ImageFormats.BGRX4444, "big")
    # decode_raw(os.path.join(path_base, "PIX_FMT_RGB48LE.bin"), "generic", 256, 128, ImageFormats.RGB48, "little")
    # decode_raw(os.path.join(path_base, "PIX_FMT_RGB48BE.bin"), "generic", 256, 128, ImageFormats.RGB48, "big")
    # decode_raw(os.path.join(path_base, "PIX_FMT_BGR48LE.bin"), "generic", 256, 128, ImageFormats.BGR48, "little")

    # pal8
    # image_decoder = ImageDecoder()
    # wrapper = PillowWrapper()
    # raw_file = FileHandler(os.path.join(path_base, "PIX_FMT_PAL8.bin"), "rb", "little")
    # raw_file_data: bytes = raw_file.read_whole_file_content()
    #
    # img_data = raw_file_data[:32768]
    # palette_data = raw_file_data[32768:]
    # decoded_image_data: bytes = image_decoder.decode_indexed_image(
    #     raw_file_data, palette_data, 256, 128, ImageFormats.PAL8_BGRA8888, "little",
    # )
    # pil_image = wrapper.get_pillow_image_from_rgba8888_data(decoded_image_data, 256, 128)
    # pil_image.show()

    # decode_raw(os.path.join(path_base, "Lena_512x512_L8.bin"), "generic", 512, 512, ImageFormats.GRAY8, "little")

    # f_name = "PIX_FMT_RGBA.bin"
    # raw_data: bytes = get_file_data(os.path.join(path_base, f_name))
    # decoded_data: bytes = decode_raw(raw_data, "generic", 256, 128, ImageFormats.RGBA8888, "little", None, 32, False)
    # encoded_data: bytes = encode_raw(decoded_data, "generic", 256, 128, ImageFormats.RGBA8888, "little", None, 32)
    # if raw_data == encoded_data:
    #     logger.info("Successful conversion!")
    # else:
    #     logger.error("Images don't match!")

    # f = open(os.path.join(path_base, f_name + "_test.bin"), "wb")
    # f.write(encoded_data)
    # f.close()


    # f_name = "PIX_FMT_RGB565LE.bin"
    # raw_data: bytes = get_file_data(os.path.join(path_base, f_name))
    # decoded_data: bytes = decode_raw(os.path.join(path_base, f_name), "generic", 256, 128, ImageFormats.RGB565, "little", None, 32, False)
    # encoded_data: bytes = encode_raw(decoded_data, "generic", 256, 128, ImageFormats.RGB565, "little", None, 16)
    #
    # if raw_data == encoded_data:
    #     logger.info("Successful conversion!")
    # else:
    #     logger.error("Images don't match!")


    f_name = "RGBA8888_PSP_SWIZZLED.bin"
    raw_data: bytes = get_file_data(os.path.join(path_base, f_name))
    decoded_data: bytes = decode_raw(raw_data, "generic", 512, 256, ImageFormats.RGBA8888, "little", "PSP", 32, False)
    encoded_data: bytes = encode_raw(decoded_data, "generic", 512, 256, ImageFormats.RGBA8888, "little", "PSP", 32)
    
    if raw_data == encoded_data:
        logger.info("Successful conversion!")
    else:
        logger.error("Images don't match!")


    logger.info("End of main... Program has been executed successfully!")
    sys.exit(0)


if __name__ == "__main__":
    main()
