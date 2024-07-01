import tkinter as tk
import string

# Caesar Cipher
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

# Monoalphabetic Cipher
def monoalphabetic_encrypt(text, key):
    alphabet = string.ascii_lowercase
    encrypted_text = ""
    for char in text:
        if char.isalpha():
            if char.isupper():
                encrypted_text += key[alphabet.index(char.lower())].upper()
            else:
                encrypted_text += key[alphabet.index(char)]
        else:
            encrypted_text += char
    return encrypted_text

def monoalphabetic_decrypt(text, key):
    return monoalphabetic_encrypt(text, key)

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
        decrypted_text += decrypt_pair(text[i:i+2])
        i += 2

    return decrypted_text

# GUI
def encrypt_text():
    plaintext = text_entry.get("1.0", "end-1c")
    selected_algorithm = algorithm_var.get()

    if selected_algorithm == "Caesar Cipher":
        shift = int(shift_entry.get())
        ciphertext = caesar_encrypt(plaintext, shift)
    elif selected_algorithm == "Monoalphabetic Cipher":
        key = key_entry.get()
        ciphertext = monoalphabetic_encrypt(plaintext, key)
    elif selected_algorithm == "Polyalphabetic Cipher":
        key = key_entry.get()
        ciphertext = polyalphabetic_encrypt(plaintext, key)
    elif selected_algorithm == "Playfair Cipher":
        key = key_entry.get()
        ciphertext = playfair_encrypt(plaintext, key)

    result_text.delete("1.0", "end")
    result_text.insert("1.0", ciphertext)

def decrypt_text():
    ciphertext = text_entry.get("1.0", "end-1c")
    selected_algorithm = algorithm_var.get()

    if selected_algorithm == "Caesar Cipher":
        shift = int(shift_entry.get())
        plaintext = caesar_decrypt(ciphertext, shift)
    elif selected_algorithm == "Monoalphabetic Cipher":
        key = key_entry.get()
        plaintext = monoalphabetic_decrypt(ciphertext, key)
    elif selected_algorithm == "Polyalphabetic Cipher":
        key = key_entry.get()
        plaintext = polyalphabetic_decrypt(ciphertext, key)
    elif selected_algorithm == "Playfair Cipher":
        key = key_entry.get()
        plaintext = playfair_decrypt(ciphertext, key)

    result_text.delete("1.0", "end")
    result_text.insert("1.0", plaintext)

# Create the GUI window
window = tk.Tk()
window.title("Text Encryption and Decryption")
window.geometry("400x400")

# Text Entry
text_label = tk.Label(window, text="Enter Text:")
text_label.pack()

text_entry = tk.Text(window, height=4)
text_entry.pack()

# Algorithm Selection
algorithm_label = tk.Label(window, text="Select Algorithm:")
algorithm_label.pack()

algorithm_var = tk.StringVar(window)
algorithm_var.set("Caesar Cipher")  # Default algorithm

algorithm_option_menu = tk.OptionMenu(window, algorithm_var, "Caesar Cipher", "Monoalphabetic Cipher", "Polyalphabetic Cipher", "Playfair Cipher")
algorithm_option_menu.pack()

# Key Entry
key_label = tk.Label(window, text="Enter Key:")
key_label.pack()

key_entry = tk.Entry(window)
key_entry.pack()

# Shift Entry (for Caesar Cipher)
shift_label = tk.Label(window, text="Enter Shift:")
shift_label.pack()

shift_entry = tk.Entry(window)
shift_entry.pack()

# Encrypt Button
encrypt_button = tk.Button(window, text="Encrypt", command=encrypt_text)
encrypt_button.pack()

# Decrypt Button
decrypt_button = tk.Button(window, text="Decrypt", command=decrypt_text)
decrypt_button.pack()

# Result Text
result_label = tk.Label(window, text="Result:")
result_label.pack()

result_text = tk.Text(window, height=4)
result_text.pack()

# Run the GUI
window.mainloop()