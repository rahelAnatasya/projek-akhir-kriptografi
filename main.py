from typing import Tuple 
import streamlit as st #karna menggunakan framework streamlit
import sqlite3 #untuk membuat database ringan
from Crypto.Cipher import ARC4, AES #untuk enkripsi pesan
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64
import hashlib
import numpy as np
from PIL import Image
import io

def vigenere_encrypt(text, key): 
    ## Kunci nya meskipun dibuat huruf kecil akan di jadiin kapital
    key = key.upper()
    
    #ini buat memperpanjang kunci agar sama dengan plainteksnya  
    key_extended = ''
    for i in range(len(text)):
        idx = i % len(key)
        key_extended += key[idx]

    result = ''
    for i in range(len(text)): 
        if text[i].isalpha():
            is_upper = text[i].isupper() #cek apakah setiap huruf kapital
            letter = text[i].upper()
            key_letter = key_extended[i].upper()
            shift = ord(key_letter) - ord('A')
            char = chr((ord(letter) - ord('A') + shift) % 26 + ord('A'))
            result += char if is_upper else char.lower()
        else:
            result += text[i] #angt=ka tidak di enkripsi dan ditambahakan tanpa ada perubahan
    return result

def vigenere_decrypt(text, key):
    # Membuat kunci yang diperpanjang
    key_extended = ''
    for i in range(len(text)):
        idx = i % len(key)
        key_extended += key[idx]

    result = ''
    for i in range(len(text)):
        if text[i].isalpha():
            is_upper = text[i].isupper()
            letter = text[i].upper()
            key_letter = key_extended[i].upper()
            shift = ord(key_letter) - ord('A')
            char = chr((ord(letter) - ord('A') - shift) % 26 + ord('A'))
            result += char if is_upper else char.lower()
        else:
            result += text[i]
    return result


@st.dialog("Konfirmasi")
def konfirmasi_hapus(title, page, selected_index):
    st.write(title)
    confirmation = st.radio("Yakin?", ['Tidak', "Yakin"])
    confirm_button = st.button("Konfirmasi")
    if confirm_button and confirmation == "Yakin":
        if page == "Pesan":
            cur.execute("DELETE FROM messages WHERE user_id=? AND title=?", (st.session_state['user'], st.session_state.messages[selected_index]["title"]))
            con.commit()
            st.session_state.messages.pop(selected_index)
        elif page == "Gambar":
            st.session_state.images.pop(selected_index)
        st.rerun()
    elif confirm_button and confirmation == "Tidak":
        st.rerun()

def login():
    st.subheader("Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        hashed_input_password = hashlib.sha256(password.encode()).hexdigest()
        cur.execute("SELECT * FROM users WHERE username=? AND password=?", (username, hashed_input_password))
        user = cur.fetchone()
        if user:
            st.success(f"Welcome {username}")
            st.session_state['user'] = user[0]
            st.rerun()
        else:
            st.error("Username atau password yang anda masukkan salah")

def register():
    st.subheader("Register")
    new_username = st.text_input("New Username")
    new_password = st.text_input("New Password", type="password")
    confirm_password = st.text_input("Confirm Password", type="password")
    if st.button("Register"):
        if new_password == confirm_password:
            hashed_password = hashlib.sha256(new_password.encode()).hexdigest()
            cur.execute("INSERT INTO users (username, password) VALUES (?, ?)", (new_username, hashed_password))
            con.commit()
            st.success("Registration successful")
            st.session_state['user'] = new_username
            st.rerun()
        else:
            st.error("Passwords do not match")

def pesan():
    if 'messages' not in st.session_state:
        cur.execute("SELECT title, encrypted_message FROM messages WHERE user_id=?", (st.session_state['user'],))
        rows = cur.fetchall()
        st.session_state['messages'] = [{"title": row[0], "text": row[1]} for row in rows]

    # Message selection and add new message
    st.sidebar.subheader("Messages")
    message_titles = [msg["title"] for msg in st.session_state.messages]

    if len(message_titles) > 0:
        selected_msg = st.sidebar.radio("Select a message", message_titles, key="selected_msg")
        

        # Display selected message text
        selected_index = message_titles.index(selected_msg)

        col1, col2 = st.columns(2)
        col1.write(st.session_state.messages[selected_index]["title"])
        if col2.button("Hapus Pesan", use_container_width=True):
            konfirmasi_hapus("Apakah anda yakin ingin menghapus pesan ini?", page='Pesan', selected_index=selected_index)

        # Encryption/Decryption options

        mode = st.radio("Mode", ["Dekripsi Pesan", "Enkripsi Pesan"])

        if mode == "Enkripsi Pesan":

            st.subheader("Encrypt Message")
            plaintext = st.text_area("Masukkan pesan yang akan dienkripsi disini", key="encrypt_message", placeholder="Pesan yang akan dienkripsi")
            key = st.text_input("Masukkan kunci enkripsi", key="encrypt_key")
            if st.button("Enkripsi Pesan"):
                if plaintext and key:
                    st.success("Pesan berhasil dienkripsi, pindah ke mode view untuk mendekripsi!")
                    st.write("Pesan terenkripsi:")
                    vigenere_result = vigenere_encrypt(text=plaintext, key=key)
                    cipher = ARC4.new(key.encode())
                    encrypted = cipher.encrypt(vigenere_result.encode())
                    st.session_state.messages[selected_index]["text"] = encrypted.hex()
                    cur.execute("INSERT INTO messages (user_id, title, encrypted_message) VALUES (?, ?, ?)", 
                                (st.session_state['user'], st.session_state.messages[selected_index]["title"], encrypted.hex()))
                    con.commit()
                    st.write(encrypted.hex())
                else:
                    st.error("Pesan dan kunci tidak boleh kosong")

        else:
            st.subheader("Pesan")
            ciphertext = st.text_area("Berikut adalah isi pesan", value=st.session_state.messages[selected_index]["text"], disabled=True)
            key = st.text_input("Masukkan kunci enkripsi", key="view_decrypt_key", value="" if st.session_state.get('clear_key', False) else None)
            if st.button("Dekripsi Pesan"):
                st.session_state.clear_key = True
                if len(ciphertext) > 1 and key:
                    arc4 = ARC4.new(key.encode())
                    decrypted = arc4.decrypt(bytes.fromhex(ciphertext))
                    try:
                        st.success("Pesan berhasil di dekripsi!")
                        st.write("Pesan:")
                        pesan_plain = decrypted.decode(errors='replace')
                        hasil = vigenere_decrypt(text=pesan_plain, key=key)

                        st.write(hasil)
                    except UnicodeDecodeError:
                        st.error("Gagal mendekripsi")
                else:
                    st.error("Pesan dan kunci tidak boleh kosong")


        # Add new message section
    new_title = st.sidebar.text_input("New message title")
    if st.sidebar.button("Add Message"):
        if new_title:
            if new_title in [msg["title"] for msg in st.session_state.messages]:
                st.sidebar.error("Judul tidak boleh duplikat")
            else:
                st.session_state.messages.append({"title": new_title, "text": ""})
                st.rerun()
        else:
            st.sidebar.error("Please enter title")



def encode_image(host_image: Image.Image, secret_image: Image.Image) -> Image.Image:

    # Validasi input
    if not isinstance(host_image, Image.Image) or not isinstance(secret_image, Image.Image):
        raise ValueError("Input harus berupa objek PIL Image")
        
    # Konversi gambar ke mode RGB jika belum
    host_image = host_image.convert('RGB')
    secret_image = secret_image.convert('RGB')
    
    # Konversi gambar ke array numpy
    host_arr = np.array(host_image, dtype=np.uint8)
    secret_arr = np.array(secret_image, dtype=np.uint8)
    
    # Hitung kapasitas maksimum host image
    max_bytes = (host_arr.size * 1) // 8  # 1 bit per byte
    if secret_arr.size > max_bytes * 8:
        raise ValueError("Gambar rahasia terlalu besar untuk disembunyikan dalam gambar host")
    
    # Resize secret image ke ukuran yang sesuai dengan kapasitas host
    new_height = int(np.sqrt(max_bytes / 3))  # 3 untuk RGB channels
    new_width = new_height
    secret_img = secret_image.resize((new_width, new_height))
    secret_arr = np.array(secret_img, dtype=np.uint8)
    
    # Simpan dimensi asli untuk decoding
    width, height = secret_arr.shape[:2]
    dimension_bits = format(width, '016b') + format(height, '016b')
    
    # Konversi secret image ke binary string
    binary_secret = dimension_bits + ''.join([format(pixel, '08b') for pixel in secret_arr.flatten()])
    
    # Modify LSB dari host image
    host_flat = host_arr.flatten()
    for i in range(len(binary_secret)):
        if i < len(host_flat):
            host_flat[i] = (host_flat[i] & 254) | int(binary_secret[i])
            
    # Reshape kembali ke dimensi asli
    stego_arr = host_flat.reshape(host_arr.shape)
    return Image.fromarray(stego_arr)

def decode_image(stego_image: Image.Image) -> Image.Image:
    # Validasi input
    if not isinstance(stego_image, Image.Image):
        raise ValueError("Input harus berupa objek PIL Image")
        
    # Konversi ke RGB jika belum
    stego_image = stego_image.convert('RGB')
    stego_arr = np.array(stego_image)
    
    # Ekstrak LSB
    binary_data = ''.join([format(pixel & 1, '01b') for pixel in stego_arr.flatten()])
    
    # Ekstrak dimensi original
    width = int(binary_data[:16], 2)
    height = int(binary_data[16:32], 2)
    binary_secret = binary_data[32:]
    
    # Validasi dimensi
    if width <= 0 or height <= 0:
        raise ValueError("Dimensi tidak valid dalam data tersembunyi")
    
    # Konversi binary ke pixels
    secret_pixels = []
    for i in range(0, len(binary_secret), 8):
        if i + 8 <= len(binary_secret):
            pixel = int(binary_secret[i:i+8], 2)
            secret_pixels.append(pixel)
    
    # Buat array dengan dimensi yang benar
    try:
        secret_arr = np.array(secret_pixels[:width*height*3], dtype=np.uint8)
        secret_arr = secret_arr.reshape((width, height, 3))
        return Image.fromarray(secret_arr)
    except ValueError as e:
        raise ValueError(f"Gagal mengekstrak gambar: {str(e)}")

def verify_steganography(original_host: Image.Image, 
                        original_secret: Image.Image, 
                        stego_image: Image.Image) -> Tuple[float, float]:
    # Hitung MSE
    host_arr = np.array(original_host, dtype=np.float64)
    stego_arr = np.array(stego_image, dtype=np.float64)
    mse = np.mean((host_arr - stego_arr) ** 2)
    
    # Hitung PSNR
    if mse == 0:
        psnr = float('inf')
    else:
        psnr = 20 * np.log10(255.0 / np.sqrt(mse))
        
    return psnr, mse

def gambar():
   
    mode = st.radio("Mode", ["Dekripsi Gambar", "Enkripsi Gambar"])

    if mode == "Enkripsi Gambar":

        st.subheader("Enkripsi Gambar")
        plainimage = st.file_uploader("Gambar yang akan dienkripsi (payload)", key="encrypt_image", type=['png', 'jpg'])
        host_image = st.file_uploader("Gambar Host", key="encrypt_image_host", type=['png', 'jpg'])
        
        if plainimage and host_image:
            # Display original images
            col1, col2 = st.columns(2)
            with col1:
                st.write("Payload Image:")
                secret_img = Image.open(plainimage).convert('RGB')
                st.image(secret_img)
                
            with col2:
                st.write("Host Image:")
                host_img = Image.open(host_image).convert('RGB')
                st.image(host_img)
            
            if st.button("Enkripsi Gambar"):
                try:
                    # Perform steganography
                    stego_image = encode_image(host_img, secret_img)
                    
                    # Display result
                    st.write("Hasil Steganografi:")
                    st.image(stego_image)
                    
                    # Save to BytesIO for downloading
                    buf = io.BytesIO()
                    stego_image.save(buf, format="PNG")
                    st.download_button(
                        label="Download Stego Image",
                        data=buf.getvalue(),
                        file_name="stego_image.png",
                        mime="image/png"
                    )
                    
                    # Save to session state
                    st.session_state['stego_image'] = stego_image
                    st.session_state['original_secret'] = secret_img
                    st.session_state['original_host'] = host_img
                    
                except Exception as e:
                    st.error(f"Error dalam proses steganografi: {str(e)}")
                
        else:
            st.error("Silakan upload kedua gambar terlebih dahulu")

    else:
        st.write("Stego Image")
        stego_file = st.file_uploader("Upload Stego Image", type=['png'])
        
        if stego_file and st.button("Dekripsi Gambar"):
            try:
                stego_img = Image.open(stego_file).convert('RGB')
                decoded_image = decode_image(stego_img)
                
                # Display results
                col1, col2 = st.columns(2)
                with col1:
                    st.write("Stego Image:")
                    st.image(stego_img)
                
                with col2:
                    st.write("Hasil Ekstraksi:")
                    st.image(decoded_image)
                    
                # Allow downloading recovered image
                buf = io.BytesIO()
                decoded_image.save(buf, format="PNG")
                st.download_button(
                    label="Download Recovered Image",
                    data=buf.getvalue(),
                    file_name="recovered_secret.png",
                    mime="image/png"
                )
                
            except Exception as e:
                st.error(f"Error dalam proses ekstraksi: {str(e)}")

def encrypt_file(file_bytes: bytes, key: str) -> tuple[bytes, bytes]:
    """Enkripsi file menggunakan AES."""
    # Generate key dan iv
    key = hashlib.sha256(key.encode()).digest()
    iv = get_random_bytes(AES.block_size)
    
    # Setup cipher
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Encrypt
    encrypted = cipher.encrypt(pad(file_bytes, AES.block_size))
    return encrypted, iv

def decrypt_file(encrypted_bytes: bytes, iv: bytes, key: str) -> bytes:
    """Dekripsi file menggunakan AES."""
    # Generate key
    key = hashlib.sha256(key.encode()).digest()
    
    # Setup cipher
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Decrypt
    decrypted = unpad(cipher.decrypt(encrypted_bytes), AES.block_size)
    return decrypted

def file():
    st.subheader("File Encryption/Decryption")
    
    mode = st.radio("Mode", ["Enkripsi File", "Dekripsi File"])
    
    if mode == "Enkripsi File":
        uploaded_file = st.file_uploader("Pilih file untuk dienkripsi", type=['txt', 'pdf', 'doc', 'docx'])
        key = st.text_input("Masukkan password enkripsi", type="password")
        
        if uploaded_file and key:
            if st.button("Enkripsi File"):
                try:
                    # Read file
                    file_bytes = uploaded_file.read()
                    
                    # Encrypt
                    encrypted, iv = encrypt_file(file_bytes, key)
                    
                    # Combine IV and encrypted data
                    combined = base64.b64encode(iv + encrypted).decode('utf-8')
                    
                    # Save encrypted file
                    st.download_button(
                        label="Download Encrypted File",
                        data=combined.encode(),
                        file_name=f"encrypted_{uploaded_file.name}",
                        mime="application/octet-stream"
                    )
                    st.success("File berhasil dienkripsi!")
                    
                except Exception as e:
                    st.error(f"Error dalam enkripsi: {str(e)}")
    else:
        uploaded_file = st.file_uploader("Pilih file terenkripsi", type=None)
        key = st.text_input("Masukkan password dekripsi", type="password")
        file_type = st.selectbox("Tipe file asli", ['txt', 'pdf', 'doc', 'docx'])
        
        if uploaded_file and key:
            if st.button("Dekripsi File"):
                try:
                    # Read encrypted data
                    combined = base64.b64decode(uploaded_file.read())
                    
                    # Split IV and encrypted data
                    iv = combined[:AES.block_size]
                    encrypted = combined[AES.block_size:]
                    
                    # Decrypt
                    decrypted = decrypt_file(encrypted, iv, key)
                    
                    # Save decrypted file
                    st.download_button(
                        label="Download Decrypted File",
                        data=decrypted,
                        file_name=f"decrypted_file.{file_type}",
                        mime="application/octet-stream"
                    )
                    st.success("File berhasil didekripsi!")
                    
                except Exception as e:
                    st.error(f"Error dalam dekripsi: {str(e)}")

def main():
    st.sidebar.title("Navigation")

    if st.session_state['user'] is None:
        page = st.sidebar.radio("", ["Login", "Register"], 0)
        if page == "Login":
            login()
        else:
            register()
    else:
        page = st.sidebar.radio("Pilih Menu", ["Pesan", "Gambar", "File"], 0)
        logout()

        if page == "Pesan":
            pesan()
        elif page == "Gambar":
            gambar()
        elif page == "File":
            file()
            
@st.dialog("Konfirmasi Logout")
def konfirmasi_logout(title):
    st.write(title)
    confirmation = st.radio("Yakin?", ['Tidak', "Yakin"])
    confirm_button = st.button("Konfirmasi")
    if confirm_button and confirmation == "Yakin":
        st.session_state['user'] = None
        st.rerun()
    elif confirm_button and confirmation == "Tidak":
        st.rerun()

def logout():
    col1, col2 = st.sidebar.columns(2)
    col1.button("Logout", key='logout', use_container_width = True)

    if st.session_state['logout']:
        konfirmasi_logout("Apakah yakin ingin logout?")

if __name__ == "__main__": #inisiasi awal
    con = sqlite3.connect("database.db") 
    cur = con.cursor()
    
    if 'user' not in st.session_state:
        st.session_state['user'] = None    
        
    main()

    if st.session_state['user'] is None:
        con.close()