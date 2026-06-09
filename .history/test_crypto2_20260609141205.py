import base64
import os

import pytest

from crypto_utils import (
    encrypt_with_key,
    decrypt_with_key,
    _get_or_create_key,
    KEY_FOLDER,
)


@pytest.fixture(autouse=True)
def _isolate_keys(monkeypatch, tmp_path):
    monkeypatch.setattr("crypto_utils.KEY_FOLDER", str(tmp_path))


class TestRoundtrip:
    def test_aes128_roundtrip(self):
        pt = "Hello AES-128-GCM"
        ct = encrypt_with_key(pt, 128)
        assert decrypt_with_key(ct, 128) == pt

    def test_aes192_roundtrip(self):
        pt = "Hello AES-192-GCM"
        ct = encrypt_with_key(pt, 192)
        assert decrypt_with_key(ct, 192) == pt

    def test_aes256_roundtrip(self):
        pt = "Hello AES-256-GCM"
        ct = encrypt_with_key(pt, 256)
        assert decrypt_with_key(ct, 256) == pt

    def test_empty_string_roundtrip(self):
        ct = encrypt_with_key("", 256)
        assert decrypt_with_key(ct, 256) == ""

    def test_none_becomes_empty_string(self):
        ct = encrypt_with_key(None, 256)
        assert decrypt_with_key(ct, 256) == ""

    def test_unicode_survives(self):
        pt = "Halo 🔐😊! @#$%^&*()"
        ct = encrypt_with_key(pt, 256)
        assert decrypt_with_key(ct, 256) == pt

    def test_long_text(self):
        pt = "A" * 100_000
        ct = encrypt_with_key(pt, 256)
        assert decrypt_with_key(ct, 256) == pt


class TestOutputFormat:
    def test_ciphertext_is_valid_base64(self):
        ct = encrypt_with_key("data", 256)
        assert isinstance(ct, str)
        base64.b64decode(ct, validate=True)

    def test_ciphertext_differs_from_plaintext(self):
        ct = encrypt_with_key("hello", 256)
        assert ct != "hello"

    def test_packet_structure(self):
        ct = encrypt_with_key("", 256)
        raw = base64.b64decode(ct)
        assert len(raw) >= 28
        assert len(raw) == 28


class TestNonDeterminism:
    def test_nonce_makes_each_run_unique(self):
        pt = "same input"
        results = {encrypt_with_key(pt, 256) for _ in range(5)}
        assert len(results) == 5


class TestErrorHandling:
    def test_invalid_base64_raises(self):
        with pytest.raises(ValueError):
            decrypt_with_key("!!!not-base64!!!", 256)

    def test_ciphertext_too_short_raises(self):
        with pytest.raises(ValueError):
            decrypt_with_key("AAAA", 256)

    def test_tampered_ciphertext_raises(self):
        pt = "tamper me"
        ct = encrypt_with_key(pt, 256)
        raw = bytearray(base64.b64decode(ct))
        raw[-1] ^= 1
        tampered = base64.b64encode(bytes(raw)).decode()
        with pytest.raises(ValueError):
            decrypt_with_key(tampered, 256)

    def test_wrong_bit_length_raises(self):
        pt = "secret"
        ct = encrypt_with_key(pt, 256)
        with pytest.raises(ValueError):
            decrypt_with_key(ct, 128)

    def test_decrypt_garbage_string_raises(self):
        with pytest.raises(ValueError):
            decrypt_with_key("U29tZVNhbXBsZUVuY3J5cHRlZERhdGFUZXN0aW5n", 256)


class TestKeyManagement:
    @pytest.mark.parametrize("bit_len,expected_bytes", [
        (128, 16),
        (192, 24),
        (256, 32),
    ])
    def test_key_length(self, bit_len, expected_bytes):
        key = _get_or_create_key(bit_len)
        assert len(key) == expected_bytes

    def test_key_is_reused(self):
        k1 = _get_or_create_key(256)
        k2 = _get_or_create_key(256)
        assert k1 == k2
