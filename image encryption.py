from tkinter import *
from tkinter import filedialog
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from PIL import Image, ImageTk

# AES encryption function
def encrypt_image():
    key = b'Sixteen byte key'
    cipher = AES.new(key, AES.MODE_ECB)
    
    # Select image file
    filename = filedialog.askopenfilename(title="Select Image")
    
    # Open the image file
    image = Image.open(filename)
    
    # Convert image to bytes
    image_bytes = image.tobytes()
    
    # Pad the image bytes to match AES block size
    padded_bytes = pad(image_bytes, AES.block_size)
    
    # Encrypt the padded bytes
    encrypted_bytes = cipher.encrypt(padded_bytes)
    
    # Create a new image from the encrypted bytes
    encrypted_image = Image.frombytes(image.mode, image.size, encrypted_bytes)
    
    # Display the encrypted image
    display_image(encrypted_image)

# AES decryption function
def decrypt_image():
    key = b'Sixteen byte key'
    cipher = AES.new(key, AES.MODE_ECB)
    
    # Select encrypted image file
    filename = filedialog.askopenfilename(title="Select Encrypted Image")
    
    # Open the encrypted image file
    encrypted_image = Image.open(filename)
    
    # Convert image to bytes
    encrypted_bytes = encrypted_image.tobytes()
    
    # Decrypt the encrypted bytes
    decrypted_bytes = cipher.decrypt(encrypted_bytes)
    
    # Unpad the decrypted bytes
    unpadded_bytes = unpad(decrypted_bytes, AES.block_size)
    
    # Create a new image from the decrypted bytes
    decrypted_image = Image.frombytes(encrypted_image.mode, encrypted_image.size, unpadded_bytes)
    
    # Display the decrypted image
    display_image(decrypted_image)

# Display image in a frame
def display_image(image):
    image = image.resize((300, 300))  # Resize image for display
    photo = ImageTk.PhotoImage(image)
    image_label.configure(image=photo)
    image_label.image = photo


# Create the GUI window
window = Tk()
window.title("AES Image Encryption/Decryption")

# Create buttons for encryption and decryption
encrypt_button = Button(window, text="Encrypt", command=encrypt_image)
encrypt_button.pack(pady=10)

decrypt_button = Button(window, text="Decrypt", command=decrypt_image)
decrypt_button.pack(pady=10)

# Create frame for displaying the image
frame = Frame(window)
frame.pack(pady=10)

# Create label for displaying the image
image_label = Label(frame)
image_label.pack()

# Run the GUI main loop
window.mainloop()