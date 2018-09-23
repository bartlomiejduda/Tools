
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


lokalizacja_skryptu = os.path.dirname(os.path.abspath(__file__)) #skrypt Pythona
parser = argparse.ArgumentParser()
parser.add_argument("plik_PAK", help="Sciezka do pliku PAK")

args = parser.parse_args()
sciezka_do_pliku_pak = args.plik_PAK
(sciezka_PAK, nazwa_PAK) = os.path.split(args.plik_PAK)
(Krotka_nazwa_PAK, extension) = os.path.splitext(nazwa_PAK) 
nazwa_listy = Krotka_nazwa_PAK + "_lista" + ".txt"

OFFSET_OGONA = 0x02F91DDA
OFFSET_KONCA_PLIKU = 0x02FA325A
pak_file = open(sciezka_do_pliku_pak, 'rb')
pak_file.seek(OFFSET_OGONA)
wielkosc_obszaru = OFFSET_KONCA_PLIKU - OFFSET_OGONA
liczba_plikow = wielkosc_obszaru / 0x40

if os.path.isfile(os.path.join(os.path.abspath(lokalizacja_skryptu), nazwa_listy)) :
            os.unlink(os.path.join(os.path.abspath(lokalizacja_skryptu), nazwa_listy))

for i in range(liczba_plikow):
            obszar_binarny = pak_file.read(0x40)
            obszar_binarny2 = obszar_binarny.split(b'\x00')[0]
            with open(os.path.join(os.path.abspath(lokalizacja_skryptu), nazwa_listy), 'ab') as output_file: 
                        output_file.write(obszar_binarny2)
                        if i != liczba_plikow-1:
                                    output_file.write('\n')
            
            
            

            
