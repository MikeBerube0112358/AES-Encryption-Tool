import os
from tkinter import Tk, Label, Button, Entry, filedialog
from tkinter.filedialog import askopenfilename, asksaveasfilename
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def encrypt_file(file_name, key, output_file):
    """Encrypt the specified file using AES encryption.
    The encrypted file is saved with the original extension plus an '.aes' suffix.
    """
    cipher = AES.new(key, AES.MODE_CBC)
    with open(file_name, 'rb') as file_to_encrypt:
        file_data = file_to_encrypt.read()
    padded_data = pad(file_data, AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    encrypted_file = cipher.iv + encrypted_data
    #Ensure the output file retains the original extension and adds '.aes'
    encrypted_file_name = output_file if output_file else file_name + '.aes'
    with open(encrypted_file_name, 'wb') as encrypted_file_out:
        encrypted_file_out.write(encrypted_file)
    return True

def decrypt_file(file_name, key, output_file):
    """Decrypt a file that was encrypted using AES encryption.
    The decrypted file is saved to the specified output path.
    """
    with open(file_name, 'rb') as file_to_decrypt:
        iv = file_to_decrypt.read(16)
        encrypted_data = file_to_decrypt.read()
    cipher = AES.new(key, AES.MODE_CBC, iv)
    original_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
    with open(output_file, 'wb') as original_file_out:
        original_file_out.write(original_data)
    return True

class AESApp:
    def __init__(self, window):
        self.window = window
        self.window.title("AES Encryption/Decryption")

        #Define custom font
        customFont = ('Helvetica', 14)  #Increase font size as needed

        #Set initial size
        window_width = 600  #Width of the window
        window_height = 200  #Height of the window

        #Get screen width and height
        screen_width = self.window.winfo_screenwidth()  #Width of the screen
        screen_height = self.window.winfo_screenheight()  #Height of the screen

        #Calculate x and y coordinates for the Tk root window
        center_x = int((screen_width / 2) - (window_width / 2))
        center_y = int((screen_height / 2) - (window_height / 2))

        #Set the dimensions of the screen and where it is placed
        self.window.geometry(f'{window_width}x{window_height}+{center_x}+{center_y}')

        self.key = None  #Will hold the encryption/decryption key

        #Encryption
        Label(window, text="File to encrypt:", font=customFont).grid(row=0, column=0, sticky='ew', padx=10, pady=10)
        self.encrypt_entry = Entry(window, font=customFont)
        self.encrypt_entry.grid(row=0, column=1, sticky='ew', padx=10, pady=10, columnspan=2)
        Button(window, text="Browse", command=self.load_file_to_encrypt, font=customFont).grid(row=0, column=3, sticky='ew', padx=10, pady=10)
        Button(window, text="Encrypt", command=self.encrypt, font=customFont).grid(row=0, column=4, sticky='ew', padx=10, pady=10)

        #Decryption
        Label(window, text="File to decrypt:", font=customFont).grid(row=1, column=0, sticky='ew', padx=10, pady=10)
        self.decrypt_entry = Entry(window, font=customFont)
        self.decrypt_entry.grid(row=1, column=1, sticky='ew', padx=10, pady=10, columnspan=2)
        Button(window, text="Browse", command=self.load_file_to_decrypt, font=customFont).grid(row=1, column=3, sticky='ew', padx=10, pady=10)
        Button(window, text="Decrypt", command=self.decrypt, font=customFont).grid(row=1, column=4, sticky='ew', padx=10, pady=10)

        #Key management
        Button(window, text="Generate Key", command=self.generate_key, font=customFont).grid(row=2, column=0, sticky='ew', padx=10, pady=10)
        Button(window, text="Load Key", command=self.load_key, font=customFont).grid(row=2, column=1, sticky='ew', padx=10, pady=10)
        self.key_status = Label(window, text="No key loaded", font=customFont)
        self.key_status.grid(row=2, column=2, sticky='ew', padx=10, pady=10, columnspan=3)

        #Configure the grid to expand the columns
        window.grid_columnconfigure(1, weight=1)
        window.grid_columnconfigure(2, weight=1)
        window.grid_rowconfigure(0, weight=1)
        window.grid_rowconfigure(1, weight=1)
        window.grid_rowconfigure(2, weight=1)

    def load_file_to_encrypt(self):
        file_name = filedialog.askopenfilename()
        self.encrypt_entry.delete(0, 'end')
        self.encrypt_entry.insert(0, file_name)

    def load_file_to_decrypt(self):
        file_name = filedialog.askopenfilename()
        self.decrypt_entry.delete(0, 'end')
        self.decrypt_entry.insert(0, file_name)

    def encrypt(self):
        """
        Encrypt the file selected by the user, save it with a '.aes' extension, and update the status.
        The user is prompted to choose a filename and location for the encrypted file.
        Displays status messages based on the success or failure of the encryption process.
        """
        if not self.key:
            self.update_status("No key loaded!", "error")
            return
        file_name = self.encrypt_entry.get()
        #Extract just the original filename, not the full path
        original_filename = os.path.basename(file_name)
        #Suggest a filename for the encrypted file that includes '.aes'
        suggested_filename = original_filename + '.aes'
        output_file = asksaveasfilename(defaultextension=".aes", initialfile=suggested_filename, filetypes=[("AES files", "*.aes")])
        if output_file:  #Check if the user selected a file
            if encrypt_file(file_name, self.key, output_file):  #Pass the output file to the function
                self.update_status("File encrypted successfully")
            else:
                self.update_status("Encryption failed!", "error")
        else:
            self.update_status("Encryption cancelled.", "error")

    def decrypt(self):
        """
        Decrypt the file selected by the user and update the status.
        The user is prompted to choose a filename and location for the decrypted file, suggesting the original name.
        Displays status messages based on the success or failure of the decryption process.
        """
        if not self.key:
            self.update_status("No key loaded!", "error")
            return
        file_name = self.decrypt_entry.get()
        #Extract just the original filename without the full path and remove the .aes extension
        original_filename = os.path.basename(file_name)
        if original_filename.lower().endswith('.aes'):  #Check if the filename ends with .aes
            suggested_filename = original_filename[:-4]  #Remove the .aes extension for the suggestion
        else:
            suggested_filename = original_filename  #Use the original filename if it doesn't end with .aes
        
        #Ask user where to save the decrypted file, suggesting the original filename
        output_file = asksaveasfilename(defaultextension="", initialfile=suggested_filename, filetypes=[("All files", "*.*")])
        if output_file:  #Check if the user selected a file
            if decrypt_file(file_name, self.key, output_file):  #Pass the output file to the function
                self.update_status("File decrypted successfully")
            else:
                self.update_status("Decryption failed!", "error")
        else:
            self.update_status("Decryption cancelled.", "error")

    def generate_key(self):
        """
        Generate a new AES encryption key, allow the user to save it to a file, and update the status.
        The user is prompted to choose a filename and location for the new key.
        Displays status messages based on the success or failure of the key generation and saving process.
        """
        #Ask user where to save the new key
        key_file_path = asksaveasfilename(defaultextension=".bin", filetypes=[("Binary files", "*.bin"), ("All files", "*.*")], title="Save key as...")
        if key_file_path:  #Check if the user selected a file
            self.key = get_random_bytes(32)  #Generate a new AES key
            with open(key_file_path, 'wb') as key_file:
                key_file.write(self.key)  #Write the key to the user-specified file
            self.update_status("New key generated and saved")
        else:
            self.update_status("Key generation cancelled.", "error")

    def load_key(self):
        """Load an AES key from a file and update the key status."""
        file_name = filedialog.askopenfilename()  #Opens a dialog for the user to select a file
        if file_name:  #Checks if a file was selected
            with open(file_name, 'rb') as key_file:  #Opens and reads the selected file
                self.key = key_file.read()  #The key data is stored in self.key
            self.update_status("Key loaded successfully")  #Updates the GUI to inform the user that the key was successfully loaded
        else:
            self.update_status("Key loading cancelled.", "error")

    def update_status(self, message, msg_type="info"):
        self.key_status['text'] = message
        if msg_type == "error":
            self.key_status['fg'] = "red"
        else:
            self.key_status['fg'] = "green"

if __name__ == '__main__':
    root = Tk()
    app = AESApp(root)
    root.mainloop()
