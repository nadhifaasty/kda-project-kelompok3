import base64
import pytest

from crypto_utils import (
    encrypt_with_key,
    decrypt_with_key,
    _get_or_create_key,
    KEY_FOLDER,
)


# ---------------------------------------------------------------------------
# Fixture: arahkan KEY_FOLDER ke folder sementara agar tidak mengganggu file
# key asli di folder notes/.
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def temp_key_folder(monkeypatch, tmp_path):
    """Setiap test menggunakan folder sementara untuk menyimpan file key."""
    monkeypatch.setattr("crypto_utils.KEY_FOLDER", str(tmp_path))


# ---------------------------------------------------------------------------
# 1-3. Enkripsi & Dekripsi AES-128/192/256-GCM
# ---------------------------------------------------------------------------

def test_aes_128_gcm_encrypt_decrypt():
    """Enkripsi dan dekripsi dengan AES-128-GCM, hasil harus sama."""
    plaintext = "Ini adalah teks rahasia dengan AES-128!"
    ciphertext = encrypt_with_key(plaintext, 128)
    decrypted = decrypt_with_key(ciphertext, 128)
    assert decrypted == plaintext


def test_aes_192_gcm_encrypt_decrypt():
    """Enkripsi dan dekripsi dengan AES-192-GCM, hasil harus sama."""
    plaintext = "Ini adalah teks rahasia dengan AES-192!"
    ciphertext = encrypt_with_key(plaintext, 192)
    decrypted = decrypt_with_key(ciphertext, 192)
    assert decrypted == plaintext


def test_aes_256_gcm_encrypt_decrypt():
    """Enkripsi dan dekripsi dengan AES-256-GCM, hasil harus sama."""
    plaintext = "Ini adalah teks rahasia dengan AES-256!"
    ciphertext = encrypt_with_key(plaintext, 256)
    decrypted = decrypt_with_key(ciphertext, 256)
    assert decrypted == plaintext


# ---------------------------------------------------------------------------
# 4. Ciphertext berupa string Base64 yang valid
# ---------------------------------------------------------------------------

def test_ciphertext_is_valid_base64():
    """Hasil encrypt_with_key() harus berupa string Base64 yang valid."""
    plaintext = "data penting"
    ciphertext = encrypt_with_key(plaintext, 256)

    assert isinstance(ciphertext, str)
    # validate=True memastikan padding dan karakter legal
    base64.b64decode(ciphertext, validate=True)


# ---------------------------------------------------------------------------
# 5. Ciphertext tidak boleh sama dengan plaintext
# ---------------------------------------------------------------------------

def test_ciphertext_not_equal_plaintext():
    """Ciphertext harus berbeda dari plaintext asli."""
    plaintext = "ini rahasia banget"
    ciphertext = encrypt_with_key(plaintext, 256)
    assert ciphertext != plaintext


# ---------------------------------------------------------------------------
# 6. Enkripsi dengan input sama menghasilkan output berbeda (nonce random)
# ---------------------------------------------------------------------------

def test_same_plaintext_different_ciphertext():
    """AES-GCM memakai nonce acak sehingga ciphertext selalu berbeda."""
    plaintext = "sama terus"
    c1 = encrypt_with_key(plaintext, 256)
    c2 = encrypt_with_key(plaintext, 256)
    assert c1 != c2


# ---------------------------------------------------------------------------
# 7. Plaintext kosong
# ---------------------------------------------------------------------------

def test_empty_string():
    """Enkripsi string kosong harus menghasilkan output yang bisa didekripsi
    kembali menjadi string kosong."""
    plaintext = ""
    ciphertext = encrypt_with_key(plaintext, 256)
    decrypted = decrypt_with_key(ciphertext, 256)
    assert decrypted == ""


# ---------------------------------------------------------------------------
# 8. Plaintext None (diubah jadi string kosong di dalam fungsi)
# ---------------------------------------------------------------------------

def test_none_plaintext():
    """None akan diubah menjadi '' oleh fungsi, hasil dekripsi harus ''."""
    ciphertext = encrypt_with_key(None, 256)
    decrypted = decrypt_with_key(ciphertext, 256)
    assert decrypted == ""


# ---------------------------------------------------------------------------
# 9. Karakter khusus dan emoji
# ---------------------------------------------------------------------------

def test_special_chars_and_emoji():
    """Karakter khusus dan emoji harus tetap terjaga setelah enkripsi-dekripsi."""
    plaintext = "Halo 🔐😊! Catatan rahasia: @#$%^&*()"
    ciphertext = encrypt_with_key(plaintext, 256)
    decrypted = decrypt_with_key(ciphertext, 256)
    assert decrypted == plaintext


# ---------------------------------------------------------------------------
# 10. Plaintext panjang (1000 x "data rahasia ")
# ---------------------------------------------------------------------------

def test_long_plaintext():
    """Teks panjang (ribuan karakter) harus tetap bisa dienkripsi-dekripsi."""
    plaintext = "data rahasia " * 1000
    ciphertext = encrypt_with_key(plaintext, 256)
    decrypted = decrypt_with_key(ciphertext, 256)
    assert decrypted == plaintext


# ---------------------------------------------------------------------------
# 11. Input Base64 tidak valid
# ---------------------------------------------------------------------------

def test_invalid_base64():
    """String yang bukan Base64 harus memicu ValueError saat didekripsi."""
    with pytest.raises(ValueError):
        decrypt_with_key("ini-bukan-base64", 256)


# ---------------------------------------------------------------------------
# 12. Data ciphertext dirusak (tampered)
# ---------------------------------------------------------------------------

def test_tampered_ciphertext():
    """Perubahan satu byte pada ciphertext harus dideteksi oleh GCM
    melalui authentication tag, sehingga memicu ValueError."""
    plaintext = "jangan ubah data ini"
    ciphertext = encrypt_with_key(plaintext, 256)

    # Ubah satu byte pada ciphertext
    raw = bytearray(base64.b64decode(ciphertext))
    raw[0] ^= 0xFF  # flip semua bit pada byte pertama
    tampered = base64.b64encode(bytes(raw)).decode("utf-8")

    with pytest.raises(ValueError):
        decrypt_with_key(tampered, 256)


# ---------------------------------------------------------------------------
# 13. Salah kunci / salah bit length
# ---------------------------------------------------------------------------

def test_wrong_key_length():
    """Ciphertext yang dienkripsi dengan AES-256-GCM tidak bisa didekripsi
    dengan AES-128-GCM karena kuncinya berbeda."""
    plaintext = "kunci harus cocok"
    ciphertext = encrypt_with_key(plaintext, 256)

    with pytest.raises(ValueError):
        decrypt_with_key(ciphertext, 128)


# ---------------------------------------------------------------------------
# 14. Panjang key sesuai bit length yang diminta
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("bit_length, expected_bytes", [
    (128, 16),
    (192, 24),
    (256, 32),
])
def test_key_length_matches_bit_length(bit_length, expected_bytes):
    """Key yang dihasilkan harus memiliki panjang bytes sesuai bit length:
    128 bit = 16 bytes, 192 bit = 24 bytes, 256 bit = 32 bytes."""
    key = _get_or_create_key(bit_length)
    assert len(key) == expected_bytes
