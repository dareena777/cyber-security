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




# uploading the image
def open_image():
    global image_data, photo, image_label
    filename = askopenfilename()
    image_data = Image.open(filename)
    image_data = image_data.resize((300, 300))
    # Convert the image to a format that can be displayed in Tkinter
    photo = ImageTk.PhotoImage(image_data)
    
    # Create a frame to hold the image label
    image_frame = customtkinter.CTkFrame(master=root, width=300, height=300)
    image_frame.pack(side=LEFT, padx=10)
    image_frame.place(x=50,y=80)
    
    # Create a label to display the image
    image_label = Label(image_frame, image=photo)
    image_label.pack()
    
    label1 = customtkinter.CTkLabel(master=root,text="Original image" ,font=("Roboto",24) )
    label1.pack()
    label1.place(x=50,y=30)
    
    


# AES encryption function
def encrypt_image():
    global image_data,image_bytes,encrypted_image,encrypted_image2,padded_bytes,encrypted_bytes, encrypted_image_label
    key = b'Sixteen byte key'
    cipher = AES.new(key, AES.MODE_ECB)
    
    # Convert image to bytes
    image_bytes = image_data.tobytes()
    
    # Pad the image bytes to match AES block size
    padded_bytes = pad(image_bytes, AES.block_size)
    
    # Encrypt the padded bytes
    encrypted_bytes = cipher.encrypt(padded_bytes)
    
    # Create a new image from the encrypted bytes
    encrypted_image = Image.frombytes(image_data.mode, image_data.size, encrypted_bytes)
   
    # Convert the image to a format that can be displayed in Tkinter
    encrypted_image2 = ImageTk.PhotoImage(encrypted_image)
    
      # Create a frame to hold the image label
    encrypted_image_frame= customtkinter.CTkFrame( master=root, width=300, height=300)
    encrypted_image_frame.pack(side=LEFT, padx=10, pady=10)
    encrypted_image_frame.place(x=380,y=80)
    
    # Create a label to display the image
    encrypted_image_label = Label(encrypted_image_frame, image=encrypted_image2)
    encrypted_image_label.pack(fill=BOTH, expand=YES)
    
    label2 = customtkinter.CTkLabel(master=root,text="Edited Image using AES algorithm " ,font=("Roboto",24) )
    label2.pack()
    label2.place(x=520,y=30) 
  

# AES decryption function
def decrypt_image():
    global image_data, encrypted_image2,encrypted_bytes,decrypted_image,decrypted_bytes,decrypted_image2
    key = b'Sixteen byte key'
    cipher = AES.new(key, AES.MODE_ECB)
    
    # Decrypt the encrypted bytes
    decrypted_bytes = cipher.decrypt(encrypted_bytes)
    
    # Unpad the decrypted bytes
    unpadded_bytes = unpad(decrypted_bytes, AES.block_size)
    
    # Create a new image from the decrypted bytes
    decrypted_image = Image.frombytes(encrypted_image.mode, encrypted_image.size, unpadded_bytes)
    
    decrypted_image2 = ImageTk.PhotoImage(decrypted_image)
    encrypted_image_label.configure(image=decrypted_image2)
    encrypted_image_label.image =decrypted_image2
    
  
 #--------------------------------------------------------------------------------------------------------------------------
 # ceaser


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

#------------------------------------------------------------------------------------------------------------------------


# Monoalphabetic Cipher
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
    
    
#----------------------------------------------------------------------------

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

#--------------------------------------------------------------------

# GUI
def encrypt_text():
    global ciphertext,plaintext,key,shift,result1
    plaintext = entry1.get()
    selected_algorithm = algorithm_option_menu.get()

    if selected_algorithm == "Caesar Cipher":
        shift = int(entry3.get())
        ciphertext = caesar_encrypt(plaintext, shift)
    elif selected_algorithm == "Monoalphabetic Cipher":
        ciphertext = monoalphabetic_encrypt(plaintext)
    elif selected_algorithm == "Polyalphabetic Cipher":
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

    if selected_algorithm == "Caesar Cipher":
        shift =int(entry3.get())
        plaintext = caesar_decrypt(ciphertext, shift)
    elif selected_algorithm == "Monoalphabetic Cipher": 
        plaintext = monoalphabetic_decrypt(ciphertext)
    elif selected_algorithm == "Polyalphabetic Cipher":
        key = entry2.get()
        plaintext = polyalphabetic_decrypt(ciphertext, key)
    elif selected_algorithm == "Playfair Cipher":
        key = entry2.get()
        plaintext = playfair_decrypt(ciphertext,key)
        
       
 
    #result_label._text.delete()
    result1.delete("1.0", "end")
    result1.insert("1.0", plaintext)
      

 
#------------------------------------------------------------------------------------------------------------------------------  
# buttons

# Encrypt Button
encrypt_button = customtkinter.CTkButton(master=frame, text="Encrypt_text", command=encrypt_text)
encrypt_button.pack()
encrypt_button.place(x=700,y=500)

# Decrypt Button
decrypt_button = customtkinter.CTkButton(master=frame, text="Decrypt_text", command=decrypt_text)
decrypt_button.pack()
decrypt_button.place(x=700,y=550)
 

open_button = customtkinter.CTkButton(master= frame ,text='Open Image', command=open_image)
open_button.pack(side=LEFT, padx=10)
open_button.place(x=250,y=30)


encrypt_button =customtkinter.CTkButton (master= frame, text="Encrypt", command=encrypt_image)
encrypt_button.pack(pady=10)
encrypt_button.place(x=700,y=150)


decrypt_button = customtkinter.CTkButton(master= frame, text="Decrypt", command=decrypt_image)
decrypt_button.pack(pady=10)
decrypt_button.place(x=700,y=190)

'''
# Encrypt Button for text
encrypt_button2 = customtkinter.CTkButton(master=frame, text="Encrypt_text", command=encrypt_text)
encrypt_button2.pack()
encrypt_button2.place(x=800, y = 510)
# Decrypt Button for text
decrypt_button2 = customtkinter.CTkButton(master= frame, text="Decrypt-text", command=decrypt_text)
decrypt_button2.pack()
decrypt_button2.place(x=800, y = 550)
'''
'''
# Create frame for displaying the image
frame = Frame(master= root)
frame.pack(pady=10)

# Create label for displaying the image
image_label = Label(frame)
image_label.pack()
'''
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

algorithm_option_menu = customtkinter.CTkOptionMenu(master=frame, values=("Caesar Cipher", "Monoalphabetic Cipher", "Polyalphabetic Cipher", "Playfair Cipher"))
algorithm_option_menu.pack()
algorithm_option_menu.place(x=700,y=450)



result1 = customtkinter.CTkTextbox(master=frame, width=200,corner_radius=0,height=30)
result1.place(x=200,y=450)
'''
label9= customtkinter.CTkLabel( master=frame,text="monoalphabetic ciphered text :" ,font=("Roboto",13)) #result label
label9.pack()
label9.place(x=15,y=500 )



result2 = customtkinter.CTkTextbox(master=frame, width=200,corner_radius=0,height=30)
result2.place(x=200,y=500)

'''


root.mainloop()