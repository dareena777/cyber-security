import customtkinter 
import tkinter as tk
from tkinter import *
import random
import math
from Crypto.Cipher import DES
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import hashlib
import numpy as np



customtkinter.set_appearance_mode('dark')
customtkinter.set_default_color_theme('dark-blue')

root = customtkinter.CTk()
root.geometry("1100x700")
root.title('cryptography')

frame = customtkinter.CTkFrame(master=root)
frame.pack(pady=20, padx=60, fill='both', expand=True)


#-----------------------------------------------------------------------------------------------------------------------------------


#calculating the module for diffie_helman
def power(x, y, p):
    res = 1
    x = x % p
    while (y > 0):
        if (y & 1):
            res = (res * x) % p
        y = y >> 1
        x = (x * x) % p
    return res

# Function to perform Diffie-Hellman key exchange
def diffie_hellman(generator, prime):
    # Alice and Bob choose secret keys
    private_key_Alice = random.randint(2, prime - 2)
    private_key_Bob = random.randint(2, prime - 2)

    # Alice sends g^a mod p to Bob
    public_key_Alice = power(generator, private_key_Alice, prime)

    # Bob sends g^b mod p to Alice
    public_key_Bob = power(generator, private_key_Bob, prime)

    # Alice computes shared secret key
    shared_secret_Alice = power(public_key_Bob, private_key_Alice, prime)

    # Bob computes shared secret key
    shared_secret_Bob = power(public_key_Alice, private_key_Bob, prime)

    # Both Alice and Bob should get the same shared secret key
    if shared_secret_Alice == shared_secret_Bob:
        return shared_secret_Alice
    else:
        return None
    
    # Function to handle Diffie-Hellman button click
def perform_diffie_hellman():
    generator = int(generator_entry.get())
    prime = int(prime_entry.get())

    # Perform Diffie-Hellman key exchange
    shared_secret = diffie_hellman(generator, prime)

    if shared_secret:
        # Display shared secret key
        result_label_df.configure(text=shared_secret)
    else:
        result_label_df.configure(text="Error")
        
#----------------------------------------------------------------------------------------------------------------------------------        
        
# Function to generate RSA keys
def generate_rsa_keys(p, q):
    n = p * q
    phi = (p - 1) * (q - 1)

    # Choose e such that 1 < e < phi and e is coprime to phi
    e = random.randint(2, phi - 1)
    while math.gcd(e, phi) != 1:
        e = random.randint(2, phi - 1)

    # Calculate d such that (d * e) % phi = 1
    d = pow(e, -1, phi)

    return ((e, n), (d, n))

# Function to encrypt a message using RSA
def rsa_encrypt(message, public_key):
    e, n = public_key
    encrypted_message = [pow(ord(char) - ord('a'), e, n) for char in message]
    return encrypted_message

# Function to decrypt a message using RSA
def rsa_decrypt(encrypted_message, private_key):
    d, n = private_key
    decrypted_message = ''.join([chr((char ** d) % n + ord('a')) for char in encrypted_message])
    return decrypted_message

# Function to convert list of numbers to string of letters
def numbers_to_letters(numbers):
    return ''.join([chr(num + ord('a')) for num in numbers])


# Function to handle RSA button click
def apply_rsa_encryption():
    p = int(p_entry.get())
    q = int(q_entry.get())

    # Generate RSA keys
    public_key, private_key = generate_rsa_keys(p, q)

    # Encrypt the plaintext
    plaintext = plaintext_entry.get()
    encrypted_message = rsa_encrypt(plaintext, public_key)
    encrypted_text = numbers_to_letters(encrypted_message)

    # Display the results
    result_label_rsa.configure(text=encrypted_text)        

# Function to handle RSA button click
def apply_rsa_decrypt():
    p = int(p_entry.get())
    q = int(q_entry.get())

    # Generate RSA keys
    public_key, private_key = generate_rsa_keys(p, q)

    # Encrypt the plaintext
    plaintext = plaintext_entry.get()
    encrypted_message = rsa_encrypt(plaintext, public_key)
   

    # Decrypt the encrypted message
    decrypted_message = rsa_decrypt(encrypted_message, private_key)
    #decrypted_text = numbers_to_letters(decrypted_message)

    # Display the results
    result_label_rsa.configure(text= decrypted_message)

#------------------------------------------------------------------------------------------------------------------------------------------------------------

# Function to handle DES encryption
def des_encrypt():
    plaintext = plaintext_entry_des.get().encode('utf-8')
    key = key_entry_des.get().encode('utf-8')

    if len(key) != 8:
        result_label_des.configure(text="Error: DES key must be 8 bytes long")
        return

    cipher = DES.new(key, DES.MODE_ECB)
    ciphertext = cipher.encrypt(plaintext)
    result_label_des.configure(text=f"Ciphertext: {ciphertext.hex().upper()}")

# Function to handle DES decryption
def des_decrypt():
    ciphertext_hex = result_label_des.cget("text").split(":")[1].strip()
    key = key_entry_des.get().encode('utf-8')

    if len(key) != 8:
        result_label_des.configure(text="Error: DES key must be 8 bytes long")
        return

    cipher = DES.new(key, DES.MODE_ECB)
    ciphertext = bytes.fromhex(ciphertext_hex)
    decrypted_text = cipher.decrypt(ciphertext).decode('utf-8')
    result_label_des.configure(text=f"Decrypted Text: {decrypted_text}")

#----------------------------------------------------------------------------------------------------------------------

def aes_encrypt():
    plaintext = plaintext_entry_AES.get().encode('utf-8')
    key = key_entry_AES.get().encode('utf-8')

    if len(key) not in [16, 24, 32]:
        result_label_AES.configure(text="Error: AES key must be 16, 24, or 32 bytes long")
        return

    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    result_label_AES.configure(text=f"Ciphertext: {ciphertext.hex().upper()}")

#------------------------------------------------------------------------------------------------------------------------------------


#md5
def md5_hash():
    input_string = plaintext_entry_s.get()
    md5_hash = hashlib.md5(input_string.encode('utf-8')).hexdigest()
    result_label_s.configure(text="MD5 hash: " + md5_hash)

#-------------------------------------------------

    
    # Function to handle Simplified DES encryption


    
        

#----------------------------------------------------------
FIXED_IP = [2, 6, 3, 1, 4, 8, 5, 7] 
FIXED_EP = [4, 1, 2, 3, 2, 3, 4, 1]
FIXED_IP_INVERSE = [4, 1, 3, 5, 7, 2, 8, 6]
FIXED_P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
FIXED_P8 = [6, 3, 7, 4, 8, 5, 10, 9] 
FIXED_P4 = [2, 4, 3, 1] 
S0 = [[1, 0, 3, 2], [3, 2, 1, 0], [0, 2, 1, 3], [3, 1, 3, 2]] 
S1 = [[0, 1, 2, 3], [2, 0, 1, 3], [3, 0, 1, 0], [2, 1, 0, 3]]
KEY = '0111111101'

def string_to_binary(string):
    binary = ''.join(format(ord(char), '08b') for char in string)
    return binary[:10]  # Take only the first 10 bits

def permutate(original, fixed_key): 
    new = '' 
    for i in fixed_key: 
        new += original[i - 1] 
    return new

def left_half(bits):
    return bits[:(len(bits)) // 2]

def right_half(bits): 
    return bits[len(bits) // 2:]

def shift(bits): 
    rotated_left_half = left_half(bits)[1:] + left_half(bits)[0]
    rotated_right_half = right_half(bits)[1:] + right_half(bits)[0]
    return rotated_left_half + rotated_right_half 

def key1(): 

    return permutate(shift(permutate(KEY, FIXED_P10)), FIXED_P8)

def key2(): 
    return permutate(shift(shift(permutate(KEY, FIXED_P10))), FIXED_P8)

def xor(bits, key):
    new = '' 
    for bit, key_bit in zip(bits, key): 
        new += str(((int(bit) + int(key_bit)) % 2)) 
    return new 

def lookup_in_sbox(bits, sbox):
    row = int(bits[0] + bits[3], 2)
    col = int(bits[1] + bits[2], 2) 
    return '{0:02b}'.format(sbox[row][col]) 

def f_k(bits, key): 
    L = left_half(bits)
    R = right_half(bits) 
    bits = permutate(R, FIXED_EP)
    
    bits = xor(bits, key)
    bits = lookup_in_sbox(left_half(bits), S0) + lookup_in_sbox(right_half(bits), S1) 
    bits = permutate(bits, FIXED_P4) 
    return xor(bits, L)

def encryptsdes():
    key=key_entry_SDES.get()
    plaintext = plaintext_entry_sdes.get()
    if len(key) != 10:
        print("Error", "Key must be 10 characters long.")
        return
    
    key_binary = string_to_binary(key)
    
    if len(plaintext) > 8:
        print("Error", "Plaintext must be up to 8 characters long.")
        return
    
    plain_text_binary = string_to_binary(plaintext)
    
    bits = permutate(plain_text_binary, FIXED_IP)
    temp = f_k(bits, key1()) 
    bits = right_half(bits) + temp 
    bits = f_k(bits, key2()) 
    ciphertext = permutate(bits + temp, FIXED_IP_INVERSE)
    return result_label_sdes.configure(text=ciphertext )   





 

#---------------------------------------------------------------------------

diffie_hellman_lable = customtkinter.CTkLabel(master=frame,text='Diffie_helman algorithm :',font=("Arial",18))
diffie_hellman_lable.pack()
diffie_hellman_lable.place(x=50,y=15)

RSA_lable = customtkinter.CTkLabel(master=frame,text='RSA algorithm :',font=("Arial",18))
RSA_lable.pack()
RSA_lable.place(x=50,y=135)

des_lable = customtkinter.CTkLabel(master=frame,text='DES algorithm :',font=("Arial",18))
des_lable.pack()
des_lable.place(x=50,y=250)


Aes_lable = customtkinter.CTkLabel(master=frame,text='AES algorithm :',font=("Arial",18))
Aes_lable.pack()
Aes_lable.place(x=50,y=350)

md5_lable = customtkinter.CTkLabel(master=frame,text='MD5 algorithm :',font=("Arial",18))
md5_lable.pack()
md5_lable.place(x=50,y=450)

sdes_lable = customtkinter.CTkLabel(master=frame,text='S_DES algorithm :',font=("Arial",18))
sdes_lable.pack()
sdes_lable.place(x=50,y=550)



#-----------------------------------------------------------------------------------------
generator_label = customtkinter.CTkLabel(master=frame, text="Enter Generator(g):",font=("Arial",14))
generator_label.pack()
generator_label.place(x=50, y=50)

generator_entry = customtkinter.CTkEntry(master=frame)
generator_entry.pack()
generator_entry.place(x=200, y=50)

prime_label = customtkinter.CTkLabel(master=frame, text="Enter Prime Number(n):",font=("Arial",14))
prime_label.pack()
prime_label.place(x=380, y=50)

prime_entry = customtkinter.CTkEntry(master=frame)
prime_entry.pack()
prime_entry.place(x=550, y=50)

result_label_df = customtkinter.CTkLabel(master=frame,font=("Arial",14),text='secret key')
result_label_df.pack()
result_label_df.place(x=700, y=80)

diffie_hellman_button = customtkinter.CTkButton(master=frame, text="Diffie-Hellman", command=perform_diffie_hellman, width=140, height=20)
diffie_hellman_button.pack(pady=10)
diffie_hellman_button.place(x=700, y=50)

#---------------------------------------------------------------------------------------------------------------------------

# Entry fields for p and q
p_label = customtkinter.CTkLabel(master=frame, text="Enter p:",font=("Arial",14))
p_label.pack()
p_label.place(x=50, y=165)

p_entry = customtkinter.CTkEntry(master=frame)
p_entry.pack()
p_entry.place(x=130, y=165)

q_label = customtkinter.CTkLabel(master=frame, text="Enter q:",font=("Arial",14))
q_label.pack()
q_label.place(x=300, y=165)

q_entry = customtkinter.CTkEntry(master=frame)
q_entry.pack()
q_entry.place(x=370, y=165)

# Entry field for plaintext
plaintext_label = customtkinter.CTkLabel(master=frame, text="Enter Plain Text:",font=("Arial",14))
plaintext_label.pack()
plaintext_label.place(x=550, y=165)

plaintext_entry = customtkinter.CTkEntry(master=frame)
plaintext_entry.pack()
plaintext_entry.place(x=670, y=165)


# Label to display results
result_label_rsa = customtkinter.CTkLabel(master=frame,text='',font=("Arial",14))
result_label_rsa.pack()
result_label_rsa.place(x=200, y=200)

result_label_rsa_1 = customtkinter.CTkLabel(master=frame,text='result:',font=("Arial",14))
result_label_rsa_1.pack()
result_label_rsa_1.place(x=50, y=200)


rsa_button_enc = customtkinter.CTkButton(master=frame, text="encrypt", command=apply_rsa_encryption, width=80, height=10)
rsa_button_enc.pack(pady=10)
rsa_button_enc.place(x=830, y=165)


rsa_button_dec = customtkinter.CTkButton(master=frame, text="decrypt", command=apply_rsa_decrypt, width=80, height=10)
rsa_button_dec.pack()
rsa_button_dec.place(x=830, y=200)

#-----------------------------------------------------------------------------------------------------------------------------------
plaintext_label_des = customtkinter.CTkLabel(master=frame, text="Enter Plain Text:")
plaintext_label_des.pack()
plaintext_label_des.place(x=50, y=285)

plaintext_entry_des = customtkinter.CTkEntry(master=frame)
plaintext_entry_des.pack()
plaintext_entry_des.place(x=150, y=285)


key_label_des = customtkinter.CTkLabel(master=frame, text=" Key (8 bytes):")
key_label_des.pack()
key_label_des.place(x=300, y=285)

key_entry_des = customtkinter.CTkEntry(master=frame)
key_entry_des.pack()
key_entry_des.place(x=400, y=285)

# Button to trigger DES encryption
encrypt_button_des = customtkinter.CTkButton(master=frame, text="Encrypt", command=des_encrypt, width=90, height=10)
encrypt_button_des.pack(pady=10)
encrypt_button_des.place(x=550, y=285)

# Button to trigger DES decryption
decrypt_button_des = customtkinter.CTkButton(master=frame, text="Decrypt", command=des_decrypt, width=90, height=10)
decrypt_button_des.pack(pady=10)
decrypt_button_des.place(x=550, y=310)

result_label_des = customtkinter.CTkLabel(master=frame, text="")
result_label_des.pack()
result_label_des.place(x=750, y=285)

result_label_dess = customtkinter.CTkLabel(master=frame, text="Results")
result_label_dess.pack()
result_label_dess.place(x=660, y=285)



#----------------------------------------------------------------------------------

plaintext_label_AES = customtkinter.CTkLabel(master=frame, text="Enter Plain Text:")
plaintext_label_AES.pack()
plaintext_label_AES.place(x=390, y=400)

plaintext_entry_AES = customtkinter.CTkEntry(master=frame)
plaintext_entry_AES.pack()
plaintext_entry_AES.place(x=500, y=400)

# Entry field for AES key
key_label_AES = customtkinter.CTkLabel(master=frame, text="Key (16, 24, or 32 bytes):")
key_label_AES.pack()
key_label_AES.place(x=50, y=400)

key_entry_AES = customtkinter.CTkEntry(master=frame)
key_entry_AES.pack()
key_entry_AES.place(x=200, y=400)


encrypt_button_AES = customtkinter.CTkButton(master=frame, text="Encrypt (AES)", command=aes_encrypt, width=100, height=15)
encrypt_button_AES.pack(pady=10)
encrypt_button_AES.place(x=660, y=400)

# Label to display results
result_label_AES = customtkinter.CTkLabel(master=frame, text="Results ")
result_label_AES.pack()
result_label_AES.place(x=570, y=435)


#---------------------------------------------------------------------------------------------------

# Entry field for plaintext
plaintext_label_s = customtkinter.CTkLabel(master=frame, text="Enter Plain Text:")
plaintext_label_s.pack()
plaintext_label_s.place(x=50, y=500)

plaintext_entry_s = customtkinter.CTkEntry(master=frame)
plaintext_entry_s.pack()
plaintext_entry_s.place(x=150, y=500)


result_label_s = customtkinter.CTkLabel(master=frame, text="Results")
result_label_s.pack()
result_label_s.place(x=300, y=500)



# Button to trigger Simplified mdf encryption
encrypt_button = customtkinter.CTkButton(master=frame, text="Encrypt", command=md5_hash, width=100, height=15)
encrypt_button.pack(pady=10)
encrypt_button.place(x=800, y=500)

#----------------------------------------------------------------------------------------------------------
encrypt_button_S = customtkinter.CTkButton(master=frame, text="Encrypt", command=encryptsdes, width=100, height=15)
encrypt_button_S.pack(pady=10)
encrypt_button_S.place(x=800, y=630)

key_label_SDES = customtkinter.CTkLabel(master=frame, text="Key (1O bytes):")
key_label_SDES.pack()
key_label_SDES.place(x=50, y=600)

key_entry_SDES = customtkinter.CTkEntry(master=frame)
key_entry_SDES.pack()
key_entry_SDES.place(x=150, y=600)

result_label_sdes = customtkinter.CTkLabel(master=frame, text="")
result_label_sdes.pack()
result_label_sdes.place(x=750, y=600)

result_label_sdess = customtkinter.CTkLabel(master=frame, text="Results")
result_label_sdess.pack()
result_label_sdess.place(x=660, y=600)

plaintext_label_sdes = customtkinter.CTkLabel(master=frame, text="Plain Text:",font=("Arial",14))
plaintext_label_sdes.pack()
plaintext_label_sdes.place(x=360, y=600)

plaintext_entry_sdes = customtkinter.CTkEntry(master=frame)
plaintext_entry_sdes.pack()
plaintext_entry_sdes.place(x=450, y=600)




root.mainloop()