
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
parser.add_argument("lista_PAK", help="Sciezka do listy")
parser.add_argument("nowypak_PAK", help="Sciezka do nowego pliku PAK")
parser.add_argument("katalog_PAK", help="Sciezka do nowego katalogu PAK")


args = parser.parse_args()
sciezka_do_listy = args.lista_PAK
katalog_glowny = args.katalog_PAK

lista = open(args.lista_PAK,"rt") 
nowypak = open(args.nowypak_PAK,"wb") 
offsety = open(os.path.abspath(__file__) + "offsety.txt", 'wt')
rozmiary = open(os.path.abspath(__file__) + "rozmiary.txt", 'wt')
nowypak.write(b"PACK" + binascii.unhexlify('FF1DF902801401FF')) #pisze domyslne wartosci do naglowka


liczba_plikow  = sum(1 for line in open(sciezka_do_listy))
offset = 12
for i in range(liczba_plikow):
    sciezka_pliku_na_liscie = lista.readline()
    (sciezka_pliku_na_liscie_okrojona, nazwa_pliku_na_liscie) = os.path.split(sciezka_pliku_na_liscie) 
    czytany_plik = open(os.path.join(katalog_glowny, sciezka_pliku_na_liscie.replace("/","\\").split(b'\x0A')[0]), "rb")

    aktualny_offset = nowypak.tell()  #w tym bloku zapisujemy offsety do pliku txt
    offsety.write(str(aktualny_offset))
    offsety.write('\n')

    nowypak.write(czytany_plik.read()) #piszemy plik do PAK
    
    aktualny_rozmiar = nowypak.tell() - aktualny_offset   #w tym bloku zapisujemy rozmiary do pliku txt
    rozmiary.write(str(aktualny_rozmiar))
    rozmiary.write('\n')
    
    offset = offset + aktualny_rozmiar #obliczamy offset koncowy, przyda sie pozniej

rozmiar_ogona = 0
lista.seek(0)
offsety = open(os.path.abspath(__file__) + "offsety.txt", 'rb')    #otwieramy pliki i wracamy w kazdym na poczatek
offsety.seek(0)
rozmiary = open(os.path.abspath(__file__) + "rozmiary.txt", 'rb')
rozmiary.seek(0)


for i in range(liczba_plikow):
    
    sciezka_pliku_na_liscie = lista.readline().split(b'\x0A')[0] #zapisujemy scioezki do PAK
    nowypak.write(sciezka_pliku_na_liscie)
    dlugosc_sciezki = len(sciezka_pliku_na_liscie)

    if dlugosc_sciezki < 56:
        ilosc_zer = 56 - dlugosc_sciezki
        nowypak.write(ilosc_zer * binascii.unhexlify('00')) #dopisujemy odpowiednio liczbe zer do sciezek w PAK
        
        przeczytane_offsety = int(offsety.readline().split(b'\x0A')[0])
        nowypak.write(struct.Struct("<l").pack(przeczytane_offsety)) #zapisuje offset w big endian
       
        przeczytane_rozmiary = int(rozmiary.readline().split(b'\x0A')[0]) #zapisuje rozmiar w big endian
        nowypak.write(struct.Struct("<l").pack(przeczytane_rozmiary))
        
        rozmiar_ogona = rozmiar_ogona + 64 #obliczamy calkowity rozmair ogona

nowypak.seek(4) #powrot do naglowka
nowypak.write(struct.Struct("<l").pack(offset)) #zapisujemy poprawny offset i rozmiar w naglowku
nowypak.write(struct.Struct("<l").pack(rozmiar_ogona))   


offsety.close()
rozmiary.close()
os.unlink(os.path.abspath(__file__) + "offsety.txt") #zamykamy pliki i je usuwamy, nie sa juz potrzebne
os.unlink(os.path.abspath(__file__) + "rozmiary.txt")