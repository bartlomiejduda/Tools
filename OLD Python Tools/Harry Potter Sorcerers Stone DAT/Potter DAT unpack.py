#ENGLISH
#Tested on Python 2.7.5
#Author of this code: ikskoks
#Contact: https://www.facebook.com/ikskoks
#This code/python script is for personal use ONLY
#It was made for XENTAX users



import argparse
import os
import sys
import time
import struct
import binascii
import linecache

lokalizacja_skryptu = os.path.dirname(os.path.abspath(__file__))
parser = argparse.ArgumentParser()
parser.add_argument("plik_DIR", help="Sciezka do pliku DIR")


args = parser.parse_args()
(sciezka_dir, nazwa_dir) = os.path.split(args.plik_DIR)
(Krotka_nazwa_dir, extension) = os.path.splitext(nazwa_dir) 

nazwa_dat = "POTTER.DAT"
pelna_sciezka_dat = os.path.join(os.path.abspath(sciezka_dir), nazwa_dat)


potter_dat = open(pelna_sciezka_dat, 'rb')
potter_dir = open(args.plik_DIR, 'rb')

liczba_plikow = potter_dir.read(4)
liczba_plikow = struct.unpack('i', liczba_plikow)[0]


for i in range(liczba_plikow):
    nazwa_pliku = potter_dir.read(12)  #czytanie danych z DIR
    nazwa_pliku = nazwa_pliku.split(b'\x00')[0]
    rozmiar_pliku = potter_dir.read(4)
    rozmiar_pliku = struct.unpack('i', rozmiar_pliku)[0]
    offset_pliku = potter_dir.read(4)
    offset_pliku = struct.unpack('i', offset_pliku)[0]
    #print nazwa_pliku, rozmiar_pliku, offset_pliku
    
    potter_dat.seek(offset_pliku) #czytanie danych z DAT
    przeczytane_dane = potter_dat.read(rozmiar_pliku)
    
    sciezka_zapisywanego_pliku = os.path.join(os.path.join(os.path.abspath(sciezka_dir), "WYPAKOWANE"), nazwa_pliku) #zapisywanie danych do plikow
    print sciezka_zapisywanego_pliku
    if not os.path.isdir(os.path.join(os.path.abspath(sciezka_dir), "WYPAKOWANE")):  
            os.makedirs(os.path.join(os.path.abspath(sciezka_dir), "WYPAKOWANE"))  
            
    with open(sciezka_zapisywanego_pliku, 'wb') as plik_wyjsciowy: 
        plik_wyjsciowy.write(przeczytane_dane)    
    
    
print "Wypakowywanie zakonczone sukcesem."   

