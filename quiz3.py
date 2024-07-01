import customtkinter 
import tkinter as tk
from tkinter import *
from tkinter.filedialog import askopenfilename
from PIL import Image, ImageTk , ImageFilter ,ImageOps , ImageDraw , ImageEnhance
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import string
from string import ascii_letters,digits
from string import*
import random
from random import shuffle


customtkinter.set_appearance_mode('dark')
customtkinter.set_default_color_theme('dark-blue')

root = customtkinter.CTk()
root.geometry("1100x650")
root.title('Encryption & Decryption')

frame = customtkinter.CTkFrame(master=root)
frame.pack(pady=20, padx=60, fill='both', expand=True)

# Polyalphabetic Cipher (Vigenere Cipher)
def polyalphabetic_encrypt(text, key):
    encrypted_text = ""
    key = key.lower()
    key_len = len(key)
    for i, char in enumerate(text):
        if char.isalpha():
            if char.isupper():
                encrypted_text += chr((ord(char) - 65 + ord(key[i % key_len]) - 97) % 26 + 65)
            else:
                encrypted_text += chr((ord(char) - 97 + ord(key[i % key_len]) - 97) % 26 + 97)
        else:
            encrypted_text += char
    return encrypted_text

def polyalphabetic_decrypt(text, key):
    decrypted_text = ""
    key = key.lower()
    key_len = len(key)
    for i, char in enumerate(text):
        if char.isalpha():
            if char.isupper():
                decrypted_text += chr((ord(char) - 65 - ord(key[i % key_len]) + 97) % 26 + 65)
            else:
                decrypted_text += chr((ord(char) - 97 - ord(key[i % key_len]) + 97) % 26 + 97)
        else:
            decrypted_text += char
    return decrypted_text

#----------------------------------------------------------------------------------------------------


# Playfair Cipher
def create_playfair_matrix(key):
    key = key.replace(" ", "").upper()
    key = key.replace("J", "I")

    matrix = []
    for char in key:
        if char not in matrix:
            matrix.append(char)

    for char in string.ascii_uppercase:
        if char not in matrix:
            matrix.append(char)

    playfair_matrix = [matrix[i:i+5] for i in range(0, 25, 5)]

    return playfair_matrix

def playfair_encrypt(text, key):
    matrix = create_playfair_matrix(key)

    def get_char_position(char):
        for i in range(5):
            for j in range(5):
                if matrix[i][j] == char:
                    return i, j

    def encrypt_pair(pair):
        row1, col1 = get_char_position(pair[0])
        row2, col2 = get_char_position(pair[1])

        if row1 == row2:
            return matrix[row1][(col1 + 1) % 5] + matrix[row2][(col2 + 1) % 5]
        elif col1 == col2:
            return matrix[(row1 + 1) % 5][col1] + matrix[(row2 + 1) % 5][col2]
        else:
            return matrix[row1][col2] + matrix[row2][col1]

    encrypted_text = ""
    text = text.replace(" ", "").upper()
    text = text.replace("J", "I")
    text_len = len(text)
    i = 0
    while i < text_len:
        if i == text_len - 1 or text[i] == text[i + 1]:
            encrypted_text += encrypt_pair(text[i] + "X")
            i += 1
        else:
            encrypted_text += encrypt_pair(text[i:i+2])
            i += 2

    return encrypted_text

def playfair_decrypt(text, key):
    matrix = create_playfair_matrix(key)

    def get_char_position(char):
        for i in range(5):
            for j in range(5):
                if matrix[i][j] == char:
                    return i, j

    def decrypt_pair(pair):
        row1, col1 = get_char_position(pair[0])
        row2, col2 = get_char_position(pair[1])

        if row1 == row2:
            return matrix[row1][(col1 - 1) % 5] + matrix[row2][(col2 - 1) % 5]
        elif col1 == col2:
            return matrix[(row1 - 1) % 5][col1] + matrix[(row2 - 1) % 5][col2]
        else:
            return matrix[row1][col2] + matrix[row2][col1]

    decrypted_text = ""
    text = text.replace(" ", "").upper()
    text_len = len(text)
    i = 0
    while i < text_len:
        # Check if there are enough characters to form a pair
        if i + 1 < text_len:
            decrypted_text += decrypt_pair(text[i:i + 2])
        else:
            # Handle the case where there's an odd number of characters in the text
            decrypted_text += text[i]
        i += 2

    return decrypted_text



def encrypt_text():
    global ciphertext,plaintext,key,shift,result1
    plaintext = entry1.get()
    selected_algorithm = algorithm_option_menu.get()

    if selected_algorithm == "Polyalphabetic Cipher":
        key = entry2.get()
        ciphertext = polyalphabetic_encrypt(plaintext, key)
    elif selected_algorithm == "Playfair Cipher":
        key = entry2.get()
        ciphertext = playfair_encrypt(plaintext, key)
        
       
    #result_label._text.delete()
    result1.delete("1.0", "end")
    result1.insert("end", ciphertext)
  
   

def decrypt_text():
    global ciphertext,plaintext,key,shift,result1
    ciphertext = result1.get('0.0','end')
    selected_algorithm = algorithm_option_menu.get()

    
    if selected_algorithm == "Polyalphabetic Cipher":
        key = entry2.get()
        plaintext = polyalphabetic_decrypt(ciphertext, key)
    elif selected_algorithm == "Playfair Cipher":
        key = entry2.get()
        plaintext = playfair_decrypt(ciphertext,key)
        
       
 
    #result_label._text.delete()
    result1.delete("1.0", "end")
    result1.insert("1.0", plaintext)
      
      
# Encrypt Button
encrypt_button = customtkinter.CTkButton(master=frame, text="Encrypt_text", command=encrypt_text)
encrypt_button.pack()
encrypt_button.place(x=700,y=100)

# Decrypt Button
decrypt_button = customtkinter.CTkButton(master=frame, text="Decrypt_text", command=decrypt_text)
decrypt_button.pack()
decrypt_button.place(x=700,y=150)

label3= customtkinter.CTkLabel( master=frame,text="Enter Your Text :" ,font=("Roboto",14)) #entry label
label3.pack()
label3.place(x=35,y=370 )

entry1 =customtkinter.CTkEntry(master=frame , placeholder_text='text',height=3)
entry1.pack(pady=12, padx=20 )
entry1.place(x=150 , y=370  )




label4= customtkinter.CTkLabel( master=frame,text="enter the key :" ,font=("Roboto",14)) #key label
label4.pack()
label4.place(x=325,y=370 )

entry2 =customtkinter.CTkEntry(master=frame , placeholder_text='key')
entry2.pack(pady=12, padx=20 )
entry2.place(x=420 , y=370  )


label7= customtkinter.CTkLabel( master=frame,text="enter the shift for 'ceaser cipher' :" ,font=("Roboto",14)) #shift label
label7.pack()
label7.place(x=580,y=370 )

entry3 =customtkinter.CTkEntry(master= frame , placeholder_text='shift')
entry3.pack(pady=12, padx=20 )
entry3.place(x=810 , y=370  )

label5= customtkinter.CTkLabel( master=frame,text="the ciphered text :" ,font=("Roboto",16)) #result label
label5.pack()
label5.place(x=35,y=450 )

algorithm_option_menu = customtkinter.CTkOptionMenu(master=frame, values=( "Polyalphabetic Cipher", "Playfair Cipher"))
algorithm_option_menu.pack()
algorithm_option_menu.place(x=700,y=450)



result1 = customtkinter.CTkTextbox(master=frame, width=200,corner_radius=0,height=30)
result1.place(x=200,y=450)
       



root.mainloop()