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
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle
import requests

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
        elif page == "Inventory":
            # Delete the inventory row
            cur.execute("DELETE FROM inventory WHERE user_id=? AND row_num=?", 
                       (st.session_state['user'], selected_index))
            con.commit()
            
            # Update remaining row numbers
            cur.execute("""
                UPDATE inventory 
                SET row_num = row_num - 1 
                WHERE user_id=? AND row_num > ?
            """, (st.session_state['user'], selected_index))
            con.commit()
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
            # Check if user is already logged in
            cur.execute("SELECT * FROM logged_in_users WHERE user_id=?", (user[0],))
            existing_session = cur.fetchone()
            
            if not existing_session:
                # Add user to logged_in_users table
                cur.execute("INSERT INTO logged_in_users (user_id) VALUES (?)", (user[0],))
                con.commit()
            
            st.success(f"Welcome {username}")
            st.session_state['user'] = user[0]
            st.session_state['authenticated'] = True
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
            
            # Get the user ID of the newly created user
            cur.execute("SELECT id FROM users WHERE username = ?", (new_username,))
            user_id = cur.fetchone()[0]
            cur.execute("INSERT INTO logged_in_users (user_id) VALUES (?)", (user_id,))
            con.commit()
            
            st.success("Registration successful")
            st.session_state['user'] = user_id  # Store the numeric ID instead of username
            st.rerun()
        else:
            st.error("Passwords do not match")

def get_inventory_data(user_id):
    """Mengambil data inventory untuk user tertentu"""
    try:
        cur.execute("""
            SELECT row_num, encrypted_data 
            FROM inventory 
            WHERE user_id=? 
            ORDER BY row_num
        """, (user_id,))
        return cur.fetchall()
    except sqlite3.Error as e:
        st.error(f"Error mengambil data: {str(e)}")
        return []

def inventory():
    # Initialize key state if not exists
    if 'key_locked' not in st.session_state:
        st.session_state['key_locked'] = False
    if 'encryption_key' not in st.session_state:
        st.session_state['encryption_key'] = None
    
    # Load table data
    st.session_state['table_data'] = get_inventory_data(st.session_state['user'])

    # Key management section
    st.subheader("Manajemen Kunci")
    col1, col2, col3 = st.columns([2, 1, 1])
    
    with col1:
        if not st.session_state['key_locked']:
            key = st.text_input("Masukkan kunci untuk enkripsi/dekripsi", type="password")
            if st.button("Buka Gembok 🔒"):
                if key:
                    # Verify key against stored key
                    if verify_table_key(st.session_state['user'], key):
                        st.session_state['encryption_key'] = key
                        st.session_state['key_locked'] = True
                        st.rerun()
                    else:
                        st.error("Kunci tidak sesuai dengan kunci yang tersimpan")
                else:
                    st.error("Kunci harus diisi")
        else:
            st.info(f"Kunci terkunci 🔒")
            if st.button("Gembok Tabel 🔓"):
                st.session_state['key_locked'] = False
                st.session_state['encryption_key'] = None
                st.rerun()

    with col2:
        if st.button("Reset Tabel"):
            st.session_state['show_reset_dialog'] = True

    # Reset confirmation dialog
    if st.session_state.get('show_reset_dialog', False):
        with st.form("reset_form"):
            st.write("Konfirmasi Reset Tabel")
            st.warning("⚠️ Semua data akan dihapus!")
            password = st.text_input("Masukkan password untuk konfirmasi", type="password")
            col1, col2 = st.columns(2)
            
            with col1:
                if st.form_submit_button("Konfirmasi"):
                    # Verify password
                    hashed_input_password = hashlib.sha256(password.encode()).hexdigest()
                    cur.execute("SELECT password FROM users WHERE username=?", (st.session_state['user'],))
                    stored_password = cur.fetchone()
                    
                    if stored_password and stored_password[0] == hashed_input_password:
                        # Reset table and delete associated key
                        cur.execute("DELETE FROM inventory WHERE user_id=?", (st.session_state['user'],))
                        cur.execute("DELETE FROM table_keys WHERE user_id=?", (st.session_state['user'],))  # Delete key from table_keys
                        con.commit()
                        st.session_state['key_locked'] = False
                        st.session_state['encryption_key'] = None
                        st.session_state['show_reset_dialog'] = False
                        st.success("Tabel berhasil direset!")
                        st.rerun()
                    else:
                        st.error("Password salah!")
            
            with col2:
                if st.form_submit_button("Batal"):
                    st.session_state['show_reset_dialog'] = False
                    st.rerun()

    # Display table
    st.subheader("Data Inventory")
    
    # Table headers
    col1, col2, col3, col4, col5 = st.columns([1, 2, 2, 2, 1])
    col1.write("No")
    col2.write("Nama Barang")
    col3.write("Jumlah")
    col4.write("Harga")
    col5.write("Aksi")

    # Display table data
    if st.session_state['table_data']:
        for row in st.session_state['table_data']:
            col1, col2, col3, col4, col5 = st.columns([1, 2, 2, 2, 1])
            col1.write(row[0])  # row_num
            
            if st.session_state['key_locked']:
                try:
                    # Decrypt data
                    arc4 = ARC4.new(st.session_state['encryption_key'].encode())
                    decrypted = arc4.decrypt(bytes.fromhex(row[1]))  # row[1] is encrypted_data
                    decrypted_text = decrypted.decode(errors='replace')
                    decoded_data = vigenere_decrypt(decrypted_text, st.session_state['encryption_key'])
                    nama, jumlah, harga = decoded_data.split('|')
                    
                    col2.write(nama)
                    col3.write(jumlah)
                    col4.write(harga)
                    
                    # Delete button only enabled when key is locked
                    if col5.button("Hapus", key=f"delete_{row[0]}"):
                        konfirmasi_hapus(
                            title=f"Hapus baris {row[0]}?",
                            page="Inventory",
                            selected_index=row[0]
                        )
                except Exception as e:
                    st.error(f"Gagal mendekripsi data: {str(e)}")
            else:
                # Display encrypted data in hex format
                encrypted_hex = row[1][:10] + "..."  # Show first 10 chars of hex
                col2.write(encrypted_hex)
                col3.write(encrypted_hex)
                col4.write(encrypted_hex)
                # Disable delete button when key is not locked
                col5.button("Hapus", key=f"delete_{row[0]}", disabled=True)

    # Add PDF export button after the table display
    if st.session_state['key_locked'] and st.session_state['table_data']:
        if st.button("Link PDF"):
            try:
                # Create PDF buffer
                pdf_buffer = io.BytesIO()
                doc = SimpleDocTemplate(pdf_buffer, pagesize=letter)
                elements = []

                # Prepare table data
                table_data = [['No', 'Nama Barang', 'Jumlah', 'Harga']]
                
                for row in st.session_state['table_data']:
                    # Decrypt data
                    arc4 = ARC4.new(st.session_state['encryption_key'].encode())
                    decrypted = arc4.decrypt(bytes.fromhex(row[1]))
                    decrypted_text = decrypted.decode(errors='replace')
                    decoded_data = vigenere_decrypt(decrypted_text, st.session_state['encryption_key'])
                    nama, jumlah, harga = decoded_data.split('|')
                    
                    table_data.append([str(row[0]), nama, jumlah, harga])

                # Create table
                table = Table(table_data, colWidths=[0.5*inch, 2*inch, 1*inch, 1*inch])
                table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 12),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                    ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
                    ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 1), (-1, -1), 10),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ]))
                
                # Create PDF with table
                elements.append(table)
                doc.build(elements)

                col1, col2 = st.columns(2)
                with col1:
                    # Existing PDF download button
                    st.download_button(
                        label="Download Inventory PDF",
                        data=pdf_buffer.getvalue(),
                        file_name="inventory.pdf",
                        mime="application/pdf"
                    )
                    
                    # Encrypt PDF for secure download
                    try:
                        # Encrypt the PDF buffer using AES
                        key = hashlib.sha256(st.session_state['encryption_key'].encode()).digest()
                        iv = get_random_bytes(AES.block_size)
                        cipher = AES.new(key, AES.MODE_CBC, iv)
                        
                        # Pad and encrypt the PDF data
                        pdf_data = pdf_buffer.getvalue()
                        encrypted_pdf = cipher.encrypt(pad(pdf_data, AES.block_size))
                        
                        # Combine IV and encrypted data
                        combined_data = base64.b64encode(iv + encrypted_pdf).decode('utf-8')
                        
                        # Offer encrypted PDF download
                        st.download_button(
                            label="Download Encrypted PDF",
                            data=combined_data.encode(),
                            file_name="inventory_encrypted.enc",
                            mime="application/octet-stream"
                        )
                        
                    except Exception as e:
                        st.error(f"Error encrypting PDF: {str(e)}")
                
                with col2:
                    try:
                        # Create chart using matplotlib
                        import matplotlib.pyplot as plt
                        
                        # Extract data for chart
                        names = []
                        quantities = []
                        prices = []
                        
                        for row in st.session_state['table_data']:
                            arc4 = ARC4.new(st.session_state['encryption_key'].encode())
                            decrypted = arc4.decrypt(bytes.fromhex(row[1]))
                            decrypted_text = decrypted.decode(errors='replace')
                            decoded_data = vigenere_decrypt(decrypted_text, st.session_state['encryption_key'])
                            nama, jumlah, harga = decoded_data.split('|')
                            
                            names.append(nama)
                            quantities.append(float(jumlah))
                            prices.append(float(harga))
                        
                        # Create figure with two subplots
                        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
                        
                        # Quantity bar chart
                        ax1.bar(names, quantities)
                        ax1.set_title('Jumlah Barang')
                        ax1.set_xticklabels(names, rotation=45, ha='right')
                        
                        # Price bar chart
                        ax2.bar(names, prices)
                        ax2.set_title('Harga Barang')
                        ax2.set_xticklabels(names, rotation=45, ha='right')
                        
                        plt.tight_layout()
                        
                        # Save chart to buffer
                        chart_buffer = io.BytesIO()
                        plt.savefig(chart_buffer, format='png', bbox_inches='tight')
                        chart_buffer.seek(0)
                        plt.close()
                        
                        # Add download button for chart
                        st.download_button(
                            label="Download Chart PNG",
                            data=chart_buffer,
                            file_name="inventory_chart.png",
                            mime="image/png"
                        )
                        
                        # Add encrypted chart using steganography
                        try:
                            # Get random host image from Unsplash
                            response = requests.get("https://unsplash.it/1000/1000")
                            host_img = Image.open(io.BytesIO(response.content))
                            
                            # Convert chart to PIL Image
                            chart_img = Image.open(chart_buffer)
                            
                            # Perform steganography
                            stego_image = encode_image(host_img, chart_img)
                            
                            stego_buffer = io.BytesIO()
                            stego_image.save(stego_buffer, format='PNG')
                            stego_buffer.seek(0)
                            
                            st.download_button(
                                label="Download Encrypted Chart (Steganography)",
                                data=stego_buffer,
                                file_name="inventory_chart_encrypted.png",
                                mime="image/png"
                            )
                            
                        except Exception as e:
                            st.error(f"Error creating encrypted chart: {str(e)}")
                
                    except Exception as e:
                        st.error(f"Error generating chart: {str(e)}")
                
            except Exception as e:
                st.error(f"Error generating PDF: {str(e)}")

    st.subheader("Tambah Barang")
    if st.session_state['key_locked']:
        col1, col2, col3, col4 = st.columns(4)
        nama_barang = col2.text_input("Nama Barang")
        jumlah = col3.number_input("Jumlah", min_value=0)
        harga = col4.number_input("Harga", min_value=0.0)

        if st.button("Tambah Barang"):
            if nama_barang:
                try:
                    row_num = len(st.session_state['table_data']) + 1
                    
                    data_string = f"{nama_barang}|{jumlah}|{harga}"
                    
                    vigenere_result = vigenere_encrypt(text=data_string, key=st.session_state['encryption_key'])
                    cipher = ARC4.new(st.session_state['encryption_key'].encode())
                    encrypted = cipher.encrypt(vigenere_result.encode())
                    encrypted_hex = encrypted.hex()

                    cur.execute("""
                        INSERT INTO inventory (user_id, row_num, encrypted_data) 
                        VALUES (?, ?, ?)
                    """, (st.session_state['user'], row_num, encrypted_hex))
                    con.commit()

                    st.session_state['table_data'] = get_inventory_data(st.session_state['user'])
                    st.success("Data berhasil ditambahkan!")
                    st.rerun()
                except Exception as e:
                    st.error(f"Gagal menambahkan data: {str(e)}")
            else:
                st.error("Nama barang harus diisi")
    else:
        st.warning("Kunci harus dikunci terlebih dahulu untuk menambah data")



def encode_image(host_image: Image.Image, secret_image: Image.Image) -> Image.Image:

    if not isinstance(host_image, Image.Image) or not isinstance(secret_image, Image.Image):
        raise ValueError("Input harus berupa objek PIL Image")
        
    host_image = host_image.convert('RGB')
    secret_image = secret_image.convert('RGB')
    
    host_arr = np.array(host_image, dtype=np.uint8)
    secret_arr = np.array(secret_image, dtype=np.uint8)
    
    max_bytes = (host_arr.size * 1) // 8  # 1 bit per byte
    if secret_arr.size > max_bytes * 8:
        raise ValueError("Gambar rahasia terlalu besar untuk disembunyikan dalam gambar host")
    
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
        page = st.sidebar.radio("Pilih Menu", ["Inventory", "Gambar", "Enkripsi / Dekripsi File"], 0)
        logout()

        if page == "Inventory":
            inventory()
        elif page == "Gambar":
            gambar()
        elif page == "Enkripsi / Dekripsi File":
            file()
            
@st.dialog("Konfirmasi Logout")
def konfirmasi_logout(title):
    st.write(title)
    confirmation = st.radio("Yakin?", ['Tidak', "Yakin"])
    confirm_button = st.button("Konfirmasi")
    if confirm_button and confirmation == "Yakin":
        # Remove user from logged_in_users table
        cur.execute("DELETE FROM logged_in_users WHERE user_id=?", (st.session_state['user'],))
        con.commit()
        
        st.session_state['user'] = None
        st.session_state['authenticated'] = False
        st.rerun()
    elif confirm_button and confirmation == "Tidak":
        st.rerun()

def logout():
    col1, col2 = st.sidebar.columns(2)
    col1.button("Logout", key='logout', use_container_width = True)

    if st.session_state['logout']:
        konfirmasi_logout("Apakah yakin ingin logout?")

def create_tables():
    """Create necessary tables if they don't exist"""
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)
    
    cur.execute("""
        CREATE TABLE IF NOT EXISTS inventory (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            row_num INTEGER NOT NULL,
            encrypted_data TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)
    
    cur.execute("""
        CREATE TABLE IF NOT EXISTS table_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            key_value TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Add new table for tracking logged in users with CASCADE
    cur.execute("""
        CREATE TABLE IF NOT EXISTS logged_in_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)
    con.commit()

def verify_table_key(user_id: str, input_key: str) -> bool:
    """Verify if the input key matches the stored key for the table"""
    cur.execute("""
        SELECT key_value 
        FROM table_keys 
        WHERE user_id = ? 
        ORDER BY created_at DESC 
        LIMIT 1
    """, (user_id,))
    stored_key = cur.fetchone()
    
    if not stored_key:
        # If no key exists, store the new key
        cur.execute("""
            INSERT INTO table_keys (user_id, key_value)
            VALUES (?, ?)
        """, (user_id, input_key))
        con.commit()
        return True
    
    # Compare with existing key
    return stored_key[0] == input_key

def reset_table(user_id: str):
    """Reset a table and its associated key"""
    # Delete table data
    if user_id == 'inventory':
        cur.execute("DELETE FROM inventory WHERE user_id=?", (st.session_state['user'],))
    else:
        cur.execute(f"DELETE FROM {user_id}")
    
    # Delete stored keys
    cur.execute("DELETE FROM table_keys WHERE user_id = ?", (user_id,))
    con.commit()

# Modify the main section to create tables on startup
if __name__ == "__main__":
    con = sqlite3.connect("database.db")
    cur = con.cursor()
    
    # Create tables if they don't exist
    create_tables()
    
    if 'user' not in st.session_state:
        # Check if there's an existing logged in user
        cur.execute("SELECT user_id FROM logged_in_users LIMIT 1")
        logged_in_user = cur.fetchone()
        
        if logged_in_user:
            st.session_state['user'] = logged_in_user[0]
            st.session_state['authenticated'] = True
        else:
            st.session_state['user'] = None
            st.session_state['authenticated'] = False
    
    main()

    if st.session_state['user'] is None:
        con.close()