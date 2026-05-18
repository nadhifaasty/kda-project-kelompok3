# crypto_utils.py
# coba doang ntar dilanjut enkripsi AES-256-GCM Anggota 2
#
# anggota 2:
# - encrypt_text() menerima string plaintext, mengembalikan string Base64
# - decrypt_text() menerima string Base64, mengembalikan string plaintext
# - Format output enkripsi: Base64-encoded string (bukan raw bytes)
# - Catatan: implementasi asli akan menyertakan IV/nonce dan auth tag
#   yang di-encode bersama ciphertext dalam satu string Base64

import base64


def encrypt_text(plaintext: str) -> str:
    """
    Mock enkripsi: encode string ke Base64.
    Implementasi asli: AES-256-GCM -> gabungkan (IV + ciphertext + auth_tag) -> Base64
    """
    return base64.b64encode(plaintext.encode("utf-8")).decode("utf-8")


def decrypt_text(ciphertext_b64: str) -> str:
    """
    Mock dekripsi: decode Base64 kembali ke string.
    Implementasi asli: Base64 -> pisahkan IV + ciphertext + auth_tag -> AES-256-GCM decrypt
    """
    return base64.b64decode(ciphertext_b64.encode("utf-8")).decode("utf-8")
