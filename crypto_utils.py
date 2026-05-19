import base64
import os
import streamlit as st
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# KEY MANAGEMENT UTK BERBAGAI BIT 
KEY_FOLDER = "notes"

def _get_or_create_key(bit_length: int) -> bytes:
    """
    Mengambil atau membuat kunci secara dinamis berdasarkan panjang bit yang dipilih (128, 192, atau 256).
    """
    key_file = os.path.join(KEY_FOLDER, f"secret_{bit_length}.key")
    
    if os.path.exists(key_file):
        with open(key_file, "rb") as kf:
            return kf.read()
    else:
        # Generate kunci baru sesuai bit_length yang diminta
        key = AESGCM.generate_key(bit_length=bit_length)
        os.makedirs(KEY_FOLDER, exist_ok=True)
        with open(key_file, "wb") as kf:
            kf.write(key)
        return key

def _get_current_bit_length() -> int:
    """
    Membaca panjang bit yang sedang dipilih user di UI Streamlit milik Orang 1.
    """
    algo_name = st.session_state.get("algoritma_dipilih", "AES-256-GCM")
    
    if "128" in algo_name:
        return 128
    elif "192" in algo_name:
        return 192
    return 256

# CORE ENKRIPSI AES-GCM ADAPTIF 
def encrypt_text(plaintext: str) -> str:
    """
    Mengenkripsi plaintext menggunakan AES-GCM dengan panjang kunci dinamis (128/192/256 bit).
    Tetap mengenkripsi string kosong agar struktur file note.enc tetap valid bagi app.py.
    """
    # Jika input None, ubah ke string kosong agar tidak error (.encode)
    if plaintext is None:
        plaintext = ""
        
    bit_length = _get_current_bit_length()
    key = _get_or_create_key(bit_length)
    aesgcm = AESGCM(key)
    
    # Nonce standar GCM sepanjang 12 bytes
    nonce = os.urandom(12)
    
    # Proses enkripsi (tetap memproses teks kosong "" agar menghasilkan ciphertext + tag yang valid)
    encrypted_bytes = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    
    # Gabungkan nonce di depan paket biner sebelum di-Base64
    final_packet = nonce + encrypted_bytes
    
    return base64.b64encode(final_packet).decode("utf-8")


def decrypt_text(ciphertext_b64: str) -> str:
    """
    Mendekripsi string Base64 kembali menjadi plaintext sesuai bit_length yang aktif.
    """
    # Jika file benar-benar kosong total (0 bytes), langsung kembalikan string kosong
    if not ciphertext_b64 or not ciphertext_b64.strip():
        return ""
        
    try:
        bit_length = _get_current_bit_length()
        key = _get_or_create_key(bit_length)
        aesgcm = AESGCM(key)
        
        # Decode string Base64 kembali ke bentuk bytes data mentah
        final_packet = base64.b64decode(ciphertext_b64.encode("utf-8"))
        
        # Pisahkan nonce (12 bytes pertama) dan data terenkripsi sisanya
        nonce = final_packet[:12]
        encrypted_bytes = final_packet[12:]
        
        # Proses dekripsi sekaligus verifikasi integritas data (Auth Tag)
        decrypted_bytes = aesgcm.decrypt(nonce, encrypted_bytes, None)
        
        return decrypted_bytes.decode("utf-8")
    except Exception as e:
        raise ValueError("Gagal melakukan dekripsi. Data rusak atau kunci tidak valid.") from e