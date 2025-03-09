"""
Copyright © 2025  Bartłomiej Duda
License: GPL-3.0 License
"""

import textwrap
import frida
import os
import sys
import frida.core
import argparse
import logging

logo = """
  FFFFF  RRRR    III  DDDD     A    
  F      R   R    I   D   D   A A   
  FFFF   RRRR     I   D   D  AAAAA  
  F      R  R     I   D   D  A   A  
  F      R   R   III  DDDD   A   A  
        """


def MENU():
    parser = argparse.ArgumentParser(
        prog='frida_script_runner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent(""))

    parser.add_argument(
        'process', help='the process that you will be injecting to')
    parser.add_argument('-o', '--out', type=str, help='provide full output directory path. (def: \'dump\')',
                        metavar="dir")
    parser.add_argument('-u', '--usb', action='store_true',
                        help='device connected over usb')
    parser.add_argument('-H', '--host', type=str,
                        help='device connected over IP')
    parser.add_argument('-v', '--verbose', action='store_true', help='verbose')
    parser.add_argument('-r', '--read-only', action='store_true',
                        help="dump read-only parts of memory. More data, more errors")
    parser.add_argument('-s', '--strings', action='store_true',
                        help='run strings on all dump files. Saved in output dir.')
    parser.add_argument('--max-size', type=int, help='maximum size of dump file in bytes (def: 20971520)',
                        metavar="bytes")
    args = parser.parse_args()
    return args


print(logo)

arguments = MENU()

print("Defining configurations...")
APP_NAME = arguments.process
USB = arguments.usb
NETWORK=False
DEBUG_LEVEL = logging.INFO
STRINGS = arguments.strings
MAX_SIZE = 20971520
PERMS = 'rw-'

if arguments.host is not None:
  NETWORK=True
  IP=arguments.host

if arguments.read_only:
    PERMS = 'r--'

if arguments.verbose:
    DEBUG_LEVEL = logging.DEBUG
logging.basicConfig(format='%(levelname)s:%(message)s', level=DEBUG_LEVEL)


print("Starting a new session...")
print("APP_NAME: " + APP_NAME)
session = None
try:
    if USB:
        print("USB Session")
        session = frida.get_usb_device().attach(APP_NAME)
    elif NETWORK:
        print("Network Session")
        print("IP: " + IP)
        device = frida.get_device_manager().add_remote_device(IP)
        pid = device.spawn([APP_NAME])
        session = device.attach(pid)
        device.resume(pid)
    else:
        print("Regular Session")
        session = frida.attach(APP_NAME)
except Exception as e:
    print("Exception occured while creating session!")
    print(str(e))
    sys.exit()



print("Starting script logic...")

def on_message(message, data):
    print("[on_message] message:", message, "data:", data)


print("Reading script content...")
script_file = open("frida_android_conanescape01_hook.js", "rt")
script_text = script_file.read()
script_file.close()



print("Loading script...")
script = session.create_script(script_text)
script.on("message", on_message)
script.load()

# make sure that script is active
input("[*] Press Enter to exit...\n")
