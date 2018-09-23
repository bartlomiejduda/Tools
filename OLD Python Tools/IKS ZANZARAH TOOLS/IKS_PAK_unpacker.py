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
parser.add_argument("plik_PAK", help="Sciezka do pliku PAK")

args = parser.parse_args()
sciezka_do_PAK = args.plik_PAK

(sciezka_PAK, nazwa_PAK) = os.path.split(args.plik_PAK)
(Krotka_nazwa_PAK, extension) = os.path.splitext(nazwa_PAK) 

plik_PAK = open(sciezka_do_PAK, 'rb')
offset_powrotu = 8
plik_PAK.seek(4)
liczba_plikow = plik_PAK.read(4)
liczba_plikow = struct.unpack('i', liczba_plikow)[0]

for i in range(liczba_plikow):
            plik_PAK.seek(offset_powrotu)
            offset_konca_listy_sciezek = 0x00078770
            
            dlugosc_sciezki = plik_PAK.read(4)              #blok z czytaniem listy plikow
            dlugosc_sciezki = struct.unpack('i', dlugosc_sciezki)[0]
            plik_PAK.read(2)
            sciezka = plik_PAK.read(dlugosc_sciezki-2)
            offset_danych = plik_PAK.read(4)
            offset_danych = struct.unpack('i', offset_danych)[0]
            rozmiar_danych = plik_PAK.read(4)
            rozmiar_danych = struct.unpack('i', rozmiar_danych)[0]
            prawdziwy_offset_danych = offset_konca_listy_sciezek + offset_danych
            offset_powrotu = plik_PAK.tell()
            
            
            plik_PAK.seek(prawdziwy_offset_danych)          #blok z czytaniem danych
            plik_PAK.read(4)
            przeczytane_dane = plik_PAK.read(rozmiar_danych-8)
            plik_PAK.read(4)
            
            
            (sciezka_bez_nazwy_pliku, nazwa_pliku) = os.path.split(sciezka)         #blok zapisywania danych
            sciezka_zapisanego_pliku = os.path.join(sciezka_PAK + sciezka_bez_nazwy_pliku)
            if not os.path.isdir(sciezka_zapisanego_pliku):  
                        os.makedirs(sciezka_zapisanego_pliku) 
            with open(os.path.join(os.path.abspath(sciezka_zapisanego_pliku), nazwa_pliku), 'wb') as plik_wyjsciowy: 
                        plik_wyjsciowy.write(przeczytane_dane)
            print sciezka_zapisanego_pliku
