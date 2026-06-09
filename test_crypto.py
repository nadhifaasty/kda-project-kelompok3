import base64
import pytest

from crypto_utils import (
    encrypt_with_key,
    decrypt_with_key,
    _get_or_create_key,
)


@pytest.fixture(autouse=True)
def _isolate_keys(monkeypatch, tmp_path):
    monkeypatch.setattr("crypto_utils.KEY_FOLDER", str(tmp_path))


class TestRoundtrip:
    def test_aes128_roundtrip(self):
        print("  -->  Enkripsi teks 'Hello AES-128-GCM' pakai kunci 128 bit, lalu")
        print("      dekripsi lagi. Pastikan hasilnya sama persis seperti awal.")
        pt = "Hello AES-128-GCM"
        ct = encrypt_with_key(pt, 128)
        assert decrypt_with_key(ct, 128) == pt

    def test_aes192_roundtrip(self):
        print("  -->  Sama seperti sebelumnya, tapi pakai kunci 192 bit.")
        pt = "Hello AES-192-GCM"
        ct = encrypt_with_key(pt, 192)
        assert decrypt_with_key(ct, 192) == pt

    def test_aes256_roundtrip(self):
        print("  -->  Sama seperti sebelumnya, tapi pakai kunci 256 bit.")
        pt = "Hello AES-256-GCM"
        ct = encrypt_with_key(pt, 256)
        assert decrypt_with_key(ct, 256) == pt

    def test_empty_string_roundtrip(self):
        print('  -->  Coba enkripsi teks kosong "".')
        print("      Hasil dekripsi harus tetap kosong, bukan error.")
        ct = encrypt_with_key("", 256)
        assert decrypt_with_key(ct, 256) == ""

    def test_none_becomes_empty_string(self):
        print("  -->  Coba enkripsi dengan input None (tidak ada teks).")
        print("      Sistem harus otomatis menganggapnya sebagai teks kosong.")
        ct = encrypt_with_key(None, 256)
        assert decrypt_with_key(ct, 256) == ""

    def test_unicode_survives(self):
        print("  -->  Coba enkripsi teks yang berisi emoji dan simbol spesial:")
        print('      "Halo 🔐😊! @#$%^&*()"')
        print("      Pastikan setelah didekripsi emoji-nya tidak rusak.")
        pt = "Halo 🔐😊! @#$%^&*()"
        ct = encrypt_with_key(pt, 256)
        assert decrypt_with_key(ct, 256) == pt

    def test_long_text(self):
        print("  -->  Coba enkripsi teks sangat panjang (100.000 huruf A).")
        print("      Pastikan teks sepanjang itu tetap bisa didekripsi dengan benar.")
        pt = "A" * 100_000
        ct = encrypt_with_key(pt, 256)
        assert decrypt_with_key(ct, 256) == pt


class TestOutputFormat:
    def test_ciphertext_is_valid_base64(self):
        print("  -->  Hasil enkripsi harus berupa teks Base64.")
        print("      Base64 itu kode yang cuma pakai huruf A-Z, angka, +, /, dan =.")
        print("      Kalau bisa di-decode tanpa error, berarti formatnya valid.")
        ct = encrypt_with_key("data", 256)
        assert isinstance(ct, str)
        base64.b64decode(ct, validate=True)

    def test_ciphertext_differs_from_plaintext(self):
        print("  -->  Pastikan teks asli berbeda dengan teks hasil enkripsi.")
        print("      Ini bukti bahwa teks kita benar-benar diacak/disandikan.")
        ct = encrypt_with_key("hello", 256)
        assert ct != "hello"

    def test_packet_structure(self):
        print("  -->  Periksa struktur paket data hasil enkripsi.")
        print("      Paket minimal 28 byte = 12 byte nonce + 16 byte authentication tag.")
        ct = encrypt_with_key("", 256)
        raw = base64.b64decode(ct)
        assert len(raw) >= 28
        assert len(raw) == 28


class TestNonDeterminism:
    def test_nonce_makes_each_run_unique(self):
        print("  -->  Enkripsi teks yang SAMA sebanyak 5 kali.")
        print("      Karena AES-GCM pakai angka acak (nonce) setiap kali,")
        print("      hasil enkripsinya harus berbeda semua. Tidak ada yang sama.")
        pt = "same input"
        results = {encrypt_with_key(pt, 256) for _ in range(5)}
        assert len(results) == 5


class TestErrorHandling:
    def test_invalid_base64_raises(self):
        print("  -->  Coba dekripsi dengan teks acak yang bukan Base64:")
        print('      "!!!not-base64!!!"')
        print("      Sistem harus menolak dan mengeluarkan error ValueError.")
        with pytest.raises(ValueError):
            decrypt_with_key("!!!not-base64!!!", 256)

    def test_ciphertext_too_short_raises(self):
        print("  -->  Coba dekripsi dengan data terlalu pendek:")
        print('      "AAAA" (kurang dari 12 byte).')
        print("      Sistem harus menolak karena tidak ada nonce yang valid.")
        with pytest.raises(ValueError):
            decrypt_with_key("AAAA", 256)

    def test_tampered_ciphertext_raises(self):
        print("  -->  Enkripsi dulu satu teks, lalu ubah 1 huruf di hasil enkripsinya.")
        print("      Coba dekripsi data yang sudah dirusak tadi.")
        print("      GCM punya authentication tag, jadi perubahan 1 bit pun terdeteksi.")
        print("      Sistem harus menolak (ValueError).")
        pt = "tamper me"
        ct = encrypt_with_key(pt, 256)
        raw = bytearray(base64.b64decode(ct))
        raw[-1] ^= 1
        tampered = base64.b64encode(bytes(raw)).decode()
        with pytest.raises(ValueError):
            decrypt_with_key(tampered, 256)

    def test_wrong_bit_length_raises(self):
        print("  -->  Enkripsi pakai kunci 256 bit, lalu coba dekripsi pakai kunci 128 bit.")
        print("      Kuncinya berbeda, jadi dekripsi harus gagal (ValueError).")
        pt = "secret"
        ct = encrypt_with_key(pt, 256)
        with pytest.raises(ValueError):
            decrypt_with_key(ct, 128)

    def test_decrypt_garbage_string_raises(self):
        print("  -->  Coba dekripsi dengan string Base64 yang valid,")
        print("      tapi sebenarnya bukan data hasil enkripsi GCM.")
        print("      Sistem harus tetap menolak karena authentication tag tidak cocok.")
        with pytest.raises(ValueError):
            decrypt_with_key("U29tZVNhbXBsZUVuY3J5cHRlZERhdGFUZXN0aW5n", 256)


class TestKeyManagement:
    @pytest.mark.parametrize("bit_len,expected_bytes", [
        (128, 16),
        (192, 24),
        (256, 32),
    ])
    def test_key_length(self, bit_len, expected_bytes):
        print(f"  -->  Kunci {bit_len} bit harus punya panjang {expected_bytes} byte.")
        print(f"      (1 byte = 8 bit, jadi {bit_len} bit = {bit_len//8} byte)")
        key = _get_or_create_key(bit_len)
        assert len(key) == expected_bytes

    def test_key_is_reused(self):
        print("  -->  Panggil fungsi bikin kunci 2 kali berturut-turut.")
        print("      Karena kunci disimpan di file, hasilnya harus sama persis.")
        k1 = _get_or_create_key(256)
        k2 = _get_or_create_key(256)
        assert k1 == k2
