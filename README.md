# Secure Notes

Aplikasi web sederhana untuk menulis dan menyimpan catatan terenkripsi. Dibuat untuk memenuhi tugas mata kuliah **Keamanan Data**.

Setiap catatan yang ditulis pengguna akan dienkripsi **sebelum** disimpan ke disk menggunakan algoritma AES-256-GCM. File yang tersimpan hanya berisi *ciphertext* dalam format Base64, sehingga tidak dapat dibaca tanpa proses dekripsi yang benar.

## Cara Install

```bash
pip install -r requirements.txt
```

## Cara Menjalankan

```bash
streamlit run app.py
```

Aplikasi akan terbuka di browser secara otomatis (biasanya di `http://localhost:8501`).

## Struktur Folder

```
├── app.py               # UI utama Streamlit (dark mode)
├── crypto_utils.py      # Modul enkripsi/dekripsi (masih mock)
├── notes/
│   └── note.enc         # File hasil enkripsi catatan
├── requirements.txt     # Daftar dependensi
└── README.md            # Dokumentasi ini
```

## Fitur Aplikasi

### `app.py`
UI aplikasi dibangun dengan Streamlit, menggunakan tema **dark mode** dengan palet warna kalem dan aksen biru.

**Halaman utama:**
- Textarea untuk menulis catatan (minimal 320px)
- Character counter di pojok kanan bawah textarea
- Status penyimpanan: badge hijau (tersimpan), kuning (menyimpan), atau merah (belum disimpan)
- Tombol "Simpan Sekarang" dan "Hapus Catatan"
- Autosave otomatis dengan debounce 2 detik setelah pengguna berhenti mengetik

**Sidebar (Pengaturan):**
- **Dropdown algoritma enkripsi**: pilihan AES-128-GCM, AES-192-GCM, atau AES-256-GCM. Keamanan akan menyesuaikan (Standar / Tinggi / Maksimum)
- **Security level badge**: menampilkan tingkat keamanan algoritma yang dipilih
- **Informasi file**: nama file aktif (`note.enc`), ukuran file hasil enkripsi
- **Informasi kunci**: panjang kunci (128/192/256 bit), mode enkripsi (GCM)
- **Waktu terakhir disimpan**
- **Jumlah karakter** catatan saat ini
- **Tombol "Buat Catatan Baru"** untuk mereset textarea

### `crypto_utils.py`
Saat ini masih berupa **mock** (placeholder) yang hanya melakukan encode/decode Base64. Modul ini akan digantikan oleh implementasi AES-256-GCM asli yang dikerjakan oleh Anggota 2.

Kontrak interface yang akan dipakai:
- `encrypt_text(plaintext: str) -> str` -- menerima string plaintext, mengembalikan string Base64
- `decrypt_text(ciphertext_b64: str) -> str` -- menerima string Base64, mengembalikan string plaintext

### `notes/note.enc`
File tempat hasil enkripsi disimpan. Format: string Base64 yang merupakan gabungan dari IV/nonce, ciphertext, dan authentication tag (pada implementasi asli).

## Prinsip Keamanan

- **Client-side encryption**: Enkripsi dilakukan sepenuhnya di sisi klien (mesin pengguna) sebelum data ditulis ke disk. Tidak ada data yang dikirim ke server eksternal.
- **Zero-server architecture**: Tidak ada server atau backend yang terlibat -- aplikasi berjalan 100% lokal di komputer pengguna.
- **Zero-Knowledge**: Plaintext tidak pernah keluar dari proses enkripsi dalam bentuk teks biasa. File `.enc` yang tersimpan hanya berisi ciphertext.
- **Storage security**: File `.enc` tidak dapat dibaca tanpa kunci yang benar. Bahkan jika seseorang memiliki akses ke file tersebut, isinya tetap aman karena terenkripsi.

## Catatan

- Modul enkripsi (`crypto_utils.py`) saat ini masih berupa mock dan belum menggunakan AES-256-GCM asli.
- Implementasi AES-128, AES-192, dan AES-256 untuk benchmarking akan ditambahkan oleh anggota tim lainnya.
- Pemilihan algoritma di sidebar hanya bersifat informatif untuk persiapan integrasi dengan modul enkripsi asli.
