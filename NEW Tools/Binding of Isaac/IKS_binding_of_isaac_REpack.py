# -*- coding: utf-8 -*-

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
import linecache

lokalizacja_skryptu = os.path.dirname(os.path.abspath(__file__))
parser = argparse.ArgumentParser()
parser.add_argument("folder_SCENES", help="Sciezka do folderu SCENES")


args = parser.parse_args()
(sciezka_SCENES, nazwa_SCENES) = os.path.split(args.folder_SCENES)
(Krotka_nazwa_SCENES, extension) = os.path.splitext(nazwa_SCENES) 
sciezka_do_SCENES = args.folder_SCENES

nazwa_skryptu = "corrossion_skrypt.txt"
pelna_sciezka_skryptu = os.path.join(os.path.abspath(lokalizacja_skryptu), nazwa_skryptu)
dane_skryptu = "dane_skryptu.txt"
pelna_sciezka_danych = os.path.join(os.path.abspath(lokalizacja_skryptu), dane_skryptu)

skrypt = open(pelna_sciezka_skryptu, 'rt')
dane = open(pelna_sciezka_danych, 'rt')

liczba_linijek_tekstu  = sum(1 for line in open(pelna_sciezka_skryptu))

for i in range(liczba_linijek_tekstu):
    przetlumaczony_tekst = skrypt.readline().split(b'\x0A')[0]
    (lokalizacja_pliku, oryginalny_tekst, numer_linijki) = dane.readline().split(b'\xFF', 3)
    aktualny_plik = os.path.abspath(lokalizacja_pliku)
    liczba_linijek_tekstu2  = sum(1 for line in open(aktualny_plik))
    with open(aktualny_plik, "rt") as aktualny_plik:    
    
        string = ""
        for i in range(int(liczba_linijek_tekstu2)):
            offset_linijki = aktualny_plik.tell()
            czytana_linijka = aktualny_plik.readline()
            if not czytana_linijka:break
            string += czytana_linijka
            if czytana_linijka.find(oryginalny_tekst) != -1:
                print i+1, oryginalny_tekst, przetlumaczony_tekst
                
        aktualny_plik = os.path.abspath(lokalizacja_pliku)        
        with open(aktualny_plik, "wt") as aktualny_plik:       
            zastapiony_tekst = string.replace(oryginalny_tekst, przetlumaczony_tekst)
            aktualny_plik.seek(0)
            aktualny_plik.write(zastapiony_tekst)

   