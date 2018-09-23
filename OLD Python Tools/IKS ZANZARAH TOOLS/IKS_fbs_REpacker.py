#ENGLISH
#Tested on Python 2.7.5
#Author of this code: Bartlomiej Duda
#Contact: https://www.facebook.com/ikskoks
#This code/python script is for personal use ONLY
#It was made for XENTAX users


import argparse
import os
import sys
import time
import struct
import binascii

parser = argparse.ArgumentParser()
parser.add_argument("skrypt", help="Sciezka do skryptu")
parser.add_argument("repack_data", help="Sciezka do repack_data")

args = parser.parse_args()
(sciezka_skryptu, nazwa_skryptu) = os.path.split(args.skrypt)
(Krotka_nazwa_skryptu, extension) = os.path.splitext(nazwa_skryptu) 
nowy_FBS_nazwa = Krotka_nazwa_skryptu.replace("_skrypt","_nowy") + ".fbs"
nowy_FBS_sciezka = sciezka_skryptu

pelna_sciezka_nowy_FBS = os.path.join(os.path.abspath(nowy_FBS_sciezka), nowy_FBS_nazwa)
pelna_sciezka_do_repack_data = args.repack_data
pelna_sciezka_skryptu =  args.skrypt


repack_data = open(pelna_sciezka_do_repack_data, 'rb')
skrypt = open(pelna_sciezka_skryptu, 'rt')
nowy_FBS = open(pelna_sciezka_nowy_FBS, 'wb')

liczba_linijek_tekstu  = sum(1 for line in open(pelna_sciezka_skryptu))

nowy_FBS.write(repack_data.read(20))

for i in range(liczba_linijek_tekstu):
    linijka_tekstu = skrypt.readline()
    dlugosc_linijki = len(linijka_tekstu)
    if i == liczba_linijek_tekstu-1:
        dlugosc_linijki = len(linijka_tekstu) + 1
    fstr = ''
    data = repack_data.read(1)
    while data != "\xff":
        fstr += str(struct.unpack("c", data)[0])
        data = repack_data.read(1)
        if data == "\xff":
            ffstr = fstr
            repack_data.read(2)
    nowy_FBS.write(struct.Struct("<l").pack(dlugosc_linijki))
    nowy_FBS.write(linijka_tekstu.split(b'\x0A')[0])
    if i == 0:
        nowy_FBS.write('')
    else:
        nowy_FBS.write('\x00')
    nowy_FBS.write(ffstr)
    
     