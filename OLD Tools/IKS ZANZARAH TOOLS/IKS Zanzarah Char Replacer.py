# -*- coding: windows-1250 -*-

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
import re

if len(sys.argv)<2:
        print "ikskoks's Zanzarah Font Raplacer"
        print "Usage: <my_tool.py> _fb0x02_skrypt.txt"

else:
        parser = argparse.ArgumentParser()
        parser.add_argument("plik_TXT", help="Sciezka do pliku TXT")  
        args = parser.parse_args()
        (sciezka_TXT, nazwa_TXT) = os.path.split(args.plik_TXT)
        (Krotka_nazwa_TXT, extension) = os.path.splitext(nazwa_TXT) 
        pelna_sciezka_do_TXT = args.plik_TXT #path to txt file
        pelna_sciezka_do_nowego_TXT = sciezka_TXT + "\\" + Krotka_nazwa_TXT + "_zm.txt" #path to new txt file
        
        stary_TXT = open(pelna_sciezka_do_TXT, 'rt') #old txt file
        nowy_TXT = open(pelna_sciezka_do_nowego_TXT, 'wt+') #new txt file
        
        numer_linijki = 0  #number of the line in text file              
        for line in stary_TXT:
                numer_linijki += 1             
                if Krotka_nazwa_TXT == "_fb0x02_skrypt" and (numer_linijki == 280
                                                             or numer_linijki == 342 #Prosze wlozyc do napedu...
                                                             or numer_linijki == 783 #sprzet
                                                             or numer_linijki == 295 #To menu pozwoli ci...
                                                             or numer_linijki == 863 #dzwiek
                                                             or numer_linijki == 308 #zrodlo dzwieku
                                                             or numer_linijki == 671 #jakosc dzwieku
                                                             or numer_linijki == 121 #srednia
                                                             or numer_linijki == 431 #po lewej z tylu
                                                             or numer_linijki == 164 #po prawej z tylu
                                                             or numer_linijki == 683 #glosnosc
                                                             or numer_linijki == 890 #informacja o jakosci
                                                             or numer_linijki == 481 #glosy 2d
                                                             or numer_linijki == 669 #dzwieki 3d
                                                             or numer_linijki == 418 #dzwieki
                                                             or numer_linijki == 722 #odwroc
                                                             or numer_linijki == 504 #Tutaj mozesz ustawic...
                                                             or numer_linijki == 582 #gestosc elementow
                                                             or numer_linijki == 678 #jakosc detali
                                                             or numer_linijki == 453 #jakosc cieni
                                                             or numer_linijki == 712 #jakosc efektow
                                                             or numer_linijki == 571 #przystosuj gre do mocy...
                                                             ):
                        nowy_TXT.write(line)                
                        
                
                else: #Replacing part. You have to change this to replace your chars.
                        nowy_TXT.write(line.replace('Ż', 'Á')
                                           .replace('Ł', 'Â')
                                           .replace('Ć', 'Ë')
                                           .replace('Ę', 'Ç')
                                           .replace('Ś', 'ß')
                                           .replace('Ą', 'Ä')
                                           .replace('Ź', 'Ý')
                                           .replace('Ń', 'Ü')
                                           
                                           .replace('ż', 'á')
                                           .replace('ł', 'â')
                                           .replace('ć', 'ë')
                                           .replace('ę', 'ç')
                                           .replace('ś', 'é')
                                           .replace('ą', 'ä')
                                           .replace('ź', 'ú')
                                           .replace('ń', 'ü')                                   
                                           )
                        
                        
                        
        stary_TXT.close()
        nowy_TXT.close()
        print "Zakonczono zamiane..." #replacing is finished...
        
        