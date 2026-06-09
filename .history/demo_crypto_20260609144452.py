import base64
import os
import sys

sys.stdout.reconfigure(encoding="utf-8")

from crypto_utils import encrypt_with_key, decrypt_with_key
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

PLAINTEXT = "Ini catatan rahasia saya 🔐"

SEP = "=" * 55


def _cbc_encrypt(plaintext: str, key: bytes, iv: bytes) -> bytes:
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    data = padder.update(plaintext.encode("utf-8")) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()


def _cbc_decrypt_raw(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


# ---------------------------------------------------------------------------
# 0. Penjelasan istilah dasar (untuk orang awam)
# ---------------------------------------------------------------------------

def demo_istilah() -> None:
    print("SEKILAS ISTILAH:")
    print("  • Plaintext   → teks asli yang ingin kita rahasiakan.")
    print("  • Enkripsi    → proses mengacak plaintext jadi kode rahasia.")
    print("  • Dekripsi    → proses mengembalikan kode rahasia jadi plaintext.")
    print("  • Kunci (key) → password khusus yang dipakai untuk enkripsi/dekripsi.")
    print("  • Ciphertext  → hasil enkripsi, kode yang tidak bisa dibaca.")
    print("  • Nonce       → angka acak yang dibuat setiap enkripsi,")
    print("                   biar hasilnya selalu beda meskipun teksnya sama.")
    print("  • Auth Tag    → segel keamanan, kalau data dirusak, segel ini rusak.")
    print("  • Base64      → cara mengubah data biner jadi teks huruf/angka,")
    print("                   biar mudah disimpan atau dikirim.\n")


# ---------------------------------------------------------------------------
# 1. Enkripsi & Dekripsi AES-GCM (128, 192, 256)
# ---------------------------------------------------------------------------

def demo_algoritma(bit_length: int, label: str) -> None:
    ciphertext = encrypt_with_key(PLAINTEXT, bit_length)
    decrypted = decrypt_with_key(ciphertext, bit_length)
    status = "BERHASIL" if decrypted == PLAINTEXT else "GAGAL"
    print(f"--- {label} ---")
    print(f"Ciphertext Base64:\n{ciphertext}\n")
    print(f"Hasil dekripsi:\n{decrypted}")
    print(f"Status: {status}, hasilnya sama persis dengan plaintext awal.\n")


# ---------------------------------------------------------------------------
# 2. Struktur ciphertext (apa isi dari string Base64 itu?)
# ---------------------------------------------------------------------------

def demo_struktur_ciphertext() -> None:
    ct = encrypt_with_key("Halo", 256)
    raw = base64.b64decode(ct)

    print(SEP)
    print("STRUKTUR CIPHERTEXT")
    print(SEP)
    print("Selama ini kita lihat ciphertext sebagai teks Base64 panjang.")
    print("Tapi sebenarnya di dalamnya ada 3 komponen:\n")
    print(f"  Panjang total paket: {len(raw)} byte")
    print()
    print("  [1] Nonce (12 byte)   → angka acak, biar tiap enkripsi unik.")
    print("  [2] Ciphertext        → data yang sudah dienkripsi.")
    print("  [3] Auth Tag (16 byte)→ segel keamanan, deteksi data rusak.")
    print()
    print("Ketiganya digabung jadi satu paket biner, lalu diubah ke Base64.")
    print("Jadi ciphertext Base64 yang kita lihat itu isinya:")
    print("  nonce + ciphertext + authentication tag\n")
    print("Contoh struktur bytes (paket untuk teks 'Halo'):")
    print(f"  Hex: {raw.hex()[:24]} | {'[nonce 12B]':>12} {raw.hex()[24:36]} | {'[cipher]':>8} {raw.hex()[36:]} | {'[tag 16B]':>9}")
    print(f"      {'↑ nonce (acak)':>31} {'↑ data terenkripsi':>22} {'↑ segel integritas':>20}")
    print()


# ---------------------------------------------------------------------------
# 3. Nonce random (ciphertext berbeda walau plaintext sama)
# ---------------------------------------------------------------------------

def demo_nonce_random() -> None:
    c1 = encrypt_with_key(PLAINTEXT, 256)
    c2 = encrypt_with_key(PLAINTEXT, 256)
    berbeda = c1 != c2
    status = "BERHASIL" if berbeda else "GAGAL"

    print(SEP)
    print("DEMO NONCE RANDOM")
    print(SEP)
    print("Plaintext yang SAMA dienkripsi DUA KALI.")
    print("Karena setiap enkripsi membuat nonce acak baru,")
    print("hasil ciphertext-nya harus berbeda.\n")
    print(f"Ciphertext 1:\n{c1}\n")
    print(f"Ciphertext 2:\n{c2}\n")
    print(f"Status: {status}, ciphertext berbeda walau plaintext sama.")
    print("(Tanpa nonce, ciphertext akan selalu identik dan membocorkan pola.)\n")


# ---------------------------------------------------------------------------
# 4. Data dirusak / tampered (auth tag mendeteksi perubahan)
# ---------------------------------------------------------------------------

def demo_tampered() -> None:
    ciphertext_asli = encrypt_with_key(PLAINTEXT, 256)
    raw_asli = bytearray(base64.b64decode(ciphertext_asli))

    raw_rusak = bytearray(raw_asli)
    raw_rusak[0] ^= 0xFF
    ciphertext_rusak = base64.b64encode(bytes(raw_rusak)).decode("utf-8")

    print(SEP)
    print("DEMO DATA RUSAK / TAMPERED")
    print(SEP)
    print("Kita rusak 1 byte pertama dari ciphertext, lalu coba dekripsi.\n")
    print(f"Ciphertext asli:\n{ciphertext_asli}\n")
    print(f"Ciphertext rusak:\n{ciphertext_rusak}\n")
    print("Perbandingan byte pertama (dalam hex):")
    print(f"  Bytes asli : {raw_asli.hex()[:8]}")
    print(f"  Bytes rusak: {raw_rusak.hex()[:8]}")
    print(f"                {'↑↑ byte ini berubah'}")
    print()

    try:
        decrypt_with_key(ciphertext_rusak, 256)
        status = "GAGAL (seharusnya error)"
    except ValueError:
        status = "BERHASIL"
    print(f"Status: {status}, AES-GCM menolak dekripsi karena auth tag tidak cocok.")
    print("(GCM punya segel keamanan, jadi perubahan 1 bit pun langsung ketahuan.)\n")


# ---------------------------------------------------------------------------
# 5. Salah kunci (wrong bit length)
# ---------------------------------------------------------------------------

def demo_salah_kunci() -> None:
    print(SEP)
    print("DEMO SALAH KUNCI")
    print(SEP)
    print("Kita enkripsi plaintext pakai kunci 256 bit,")
    print("lalu coba dekripsi pakai kunci 128 bit.\n")
    print("Ibaratnya: kita buka gembok dengan kunci yang salah.\n")

    ct = encrypt_with_key(PLAINTEXT, 256)
    print(f"Ciphertext (dengan kunci 256 bit):\n{ct}\n")

    try:
        decrypt_with_key(ct, 128)
        print("Hasil dekripsi: ❌ GAGAL (seharusnya tidak berhasil)")
    except ValueError:
        print("Hasil dekripsi: ✅ DITOLAK — kunci 128 bit tidak cocok dengan ciphertext 256 bit.")
    print()


# ---------------------------------------------------------------------------
# 6. Perbandingan GCM vs CBC saat data dirusak
# ---------------------------------------------------------------------------

def demo_perbandingan_cbc() -> None:
    KEY = os.urandom(32)
    IV = os.urandom(16)

    cbc_raw = _cbc_encrypt(PLAINTEXT, KEY, IV)
    cbc_tampered = bytearray(cbc_raw)
    cbc_tampered[0] ^= 0xFF

    gcm_raw = base64.b64decode(encrypt_with_key(PLAINTEXT, 256))
    gcm_tampered = bytearray(gcm_raw)
    gcm_tampered[0] ^= 0xFF

    print(SEP)
    print("PERBANDINGAN: GCM vs CBC SAAT DATA DIRUSAK")
    print(SEP)
    print("Kedua ciphertext dirusak 1 byte pada posisi yang sama.\n")

    print("--- AES-256-GCM ---")
    gcm_rusak_b64 = base64.b64encode(bytes(gcm_tampered)).decode("utf-8")
    try:
        decrypt_with_key(gcm_rusak_b64, 256)
        print("Hasil dekripsi: ❌ GAGAL (seharusnya tidak sampai sini)")
    except ValueError:
        print("Hasil dekripsi: ✅ DITOLAK — auth tag mendeteksi perubahan.")
    print()

    print("--- AES-256-CBC ---")
    try:
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        hasil = (
            unpadder.update(_cbc_decrypt_raw(bytes(cbc_tampered), KEY, IV))
            + unpadder.finalize()
        ).decode("utf-8", errors="replace")
        print(f"Hasil dekripsi: ✅ BERHASIL (data rusak TIDAK TERDETEKSI)")
        print(f"  Output: {repr(hasil)}")
    except Exception as e:
        print(f"Hasil dekripsi: ⚠️  Error ({type(e).__name__}) — efek samping, bukan fitur keamanan.")
    print()

    print("KESIMPULAN PERBANDINGAN:")
    print("- GCM: ada auth tag → INTEGRITAS TERJAMIN.")
    print("- CBC: tidak ada auth tag → tidak bisa deteksi perubahan data.")
    print("  (Padding error kadang terjadi, tapi itu bukan fitur keamanan.")
    print("   Malah, celah padding ini bisa dieksploitasi lewat padding oracle attack.)")
    print()


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------

def main() -> None:
    print(SEP)
    print("  DEMO ENKRIPSI AES-GCM — SECURE NOTES")
    print(SEP)
    print()

    demo_istilah()

    print(SEP)
    print(" 1. ENKRIPSI & DEKRIPSI (128, 192, 256 BIT)")
    print(SEP)
    print(f"Plaintext awal:\n{PLAINTEXT}\n")
    demo_algoritma(128, "AES-128-GCM")
    demo_algoritma(192, "AES-192-GCM")
    demo_algoritma(256, "AES-256-GCM")

    demo_struktur_ciphertext()
    demo_nonce_random()
    demo_tampered()
    demo_salah_kunci()
    demo_perbandingan_cbc()

    print(SEP)
    print("  KESIMPULAN")
    print(SEP)
    print("✅ Plaintext berhasil dienkripsi jadi ciphertext Base64.")
    print("✅ Ciphertext bisa didekripsi kembali jika kunci cocok dan data utuh.")
    print("✅ Nonce acak → ciphertext selalu berbeda walau plaintext sama.")
    print("✅ Auth tag → perubahan 1 bit pun bisa dideteksi.")
    print("✅ Kunci berbeda → dekripsi gagal (keamanan terjaga).")
    print("❌ CBC tidak punya auth tag → data rusak tidak terdeteksi.")
    print()


if __name__ == "__main__":
    main()
