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


def caesar_encrypt(text, shift):
    encrypted_text = ""
    for char in text:
        if char.isalpha():
            if char.isupper():
                encrypted_text += chr((ord(char) - 65 + shift) % 26 + 65)
            else:
                encrypted_text += chr((ord(char) - 97 + shift) % 26 + 97)
        else:
            encrypted_text += char
    return encrypted_text

def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)
#-------------------------------------------------------------------------
def generate_key():
    alphabet = list(string.ascii_lowercase)
    random.shuffle(alphabet)
    return alphabet

def monoalphabetic_encrypt(text):
     encrypted_text = ""
     for char in text:
        if char == " ":
            encrypted_text += " "
        elif char in mapping:
           encrypted_text += mapping[char]
           
     return encrypted_text

key = generate_key()
mapping = {}
for i in range(len(string.ascii_lowercase)):
    mapping[string.ascii_lowercase[i]] = key[i]
    
    
def monoalphabetic_decrypt(text):
    decrypted_text = ""
    for char in  text:
        if char == " ":
            decrypted_text  += " "
        elif char in mapping.values():
            for key, value in mapping.items():
                if char == value:
                    decrypted_text += key
                    break
                
    return decrypted_text

def encrypt_text():
    global ciphertext,plaintext,key,shift,result1
    plaintext = entry1.get()
    selected_algorithm = algorithm_option_menu.get()

    if selected_algorithm == "Caesar Cipher":
        shift = int(entry3.get())
        ciphertext = caesar_encrypt(plaintext, shift)
    elif selected_algorithm == "Monoalphabetic Cipher":
        ciphertext = monoalphabetic_encrypt(plaintext)
   
          
    #result_label._text.delete()
    result1.delete("1.0", "end")
    result1.insert("end", ciphertext)
    
def decrypt_text():
    global ciphertext,plaintext,key,shift,result1
    ciphertext = result1.get('0.0','end')
    selected_algorithm = algorithm_option_menu.get()

    if selected_algorithm == "Caesar Cipher":
        shift =int(entry3.get())
        plaintext = caesar_decrypt(ciphertext, shift)
    elif selected_algorithm == "Monoalphabetic Cipher": 
        plaintext = monoalphabetic_decrypt(ciphertext)
    

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
label3.place(x=35,y=70 )

entry1 =customtkinter.CTkEntry(master=frame , placeholder_text='text',height=3)
entry1.pack(pady=12, padx=20 )
entry1.place(x=150 , y=70  )




label4= customtkinter.CTkLabel( master=frame,text="enter the key :" ,font=("Roboto",14)) #key label
label4.pack()
label4.place(x=325,y=70 )

entry2 =customtkinter.CTkEntry(master=frame , placeholder_text='key')
entry2.pack(pady=12, padx=20 )
entry2.place(x=420 , y=70  )


label7= customtkinter.CTkLabel( master=frame,text="enter the shift for 'ceaser cipher' :" ,font=("Roboto",14)) #shift label
label7.pack()
label7.place(x=580,y=70 )

entry3 =customtkinter.CTkEntry(master= frame , placeholder_text='shift')
entry3.pack(pady=12, padx=20 )
entry3.place(x=810 , y=70  )

label5= customtkinter.CTkLabel( master=frame,text="the ciphered text :" ,font=("Roboto",16)) #result label
label5.pack()
label5.place(x=35,y=150 )

algorithm_option_menu = customtkinter.CTkOptionMenu(master=frame, values=("Caesar Cipher", "Monoalphabetic Cipher"))
algorithm_option_menu.pack()
algorithm_option_menu.place(x=700,y=200)



result1 = customtkinter.CTkTextbox(master=frame, width=200,corner_radius=0,height=30)
result1.place(x=200,y=150)    


root.mainloop()












































