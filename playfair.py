import tkinter as tk
from itertools import product

def generate_playfair_table(key):
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    key = key.upper().replace("J", "I")
    key_set = set(key)
    remaining_chars = [char for char in alphabet if char not in key_set]
    playfair_table = [list(key[i:i+5]) for i in range(0, len(key), 5)]

    for char in remaining_chars:
        playfair_table.append(char)

    return playfair_table

def decrypt_playfair(ciphertext, key):
    playfair_table = generate_playfair_table(key)
    ciphertext = ciphertext.upper().replace("J", "I")
    pairs = [(ciphertext[i], ciphertext[i+1]) for i in range(0, len(ciphertext), 2)]
    plaintext = ""

    for pair in pairs:
        pair_coords = [get_coordinates(char, playfair_table) for char in pair]
        if pair_coords[0][0] == pair_coords[1][0]:  # Same row
            plaintext += playfair_table[pair_coords[0][0]][(pair_coords[0][1] - 1) % 5]
            plaintext += playfair_table[pair_coords[1][0]][(pair_coords[1][1] - 1) % 5]
        elif pair_coords[0][1] == pair_coords[1][1]:  # Same column
            plaintext += playfair_table[(pair_coords[0][0] - 1) % 5][pair_coords[0][1]]
            plaintext += playfair_table[(pair_coords[1][0] - 1) % 5][pair_coords[1][1]]
        else:
            plaintext += playfair_table[pair_coords[0][0]][pair_coords[1][1]]
            plaintext += playfair_table[pair_coords[1][0]][pair_coords[0][1]]

    return plaintext

def get_coordinates(char, table):
    for i, row in enumerate(table):
        if char in row:
            return i, row.index(char)

def decrypt_button_click():
    ciphertext = ciphertext_entry.get()
    key = key_entry.get()
    decrypted_text = decrypt_playfair(ciphertext, key)
    result_label.config(text=f"Decrypted Text: {decrypted_text}")

# GUI Setup
root = tk.Tk()
root.title("Playfair Decryption")

ciphertext_label = tk.Label(root, text="Enter Ciphertext:")
ciphertext_label.pack()

ciphertext_entry = tk.Entry(root)
ciphertext_entry.pack()

key_label = tk.Label(root, text="Enter Key:")
key_label.pack()

key_entry = tk.Entry(root)
key_entry.pack()

decrypt_button = tk.Button(root, text="Decrypt", command=decrypt_button_click)
decrypt_button.pack()

result_label = tk.Label(root, text="")
result_label.pack()

root.mainloop()