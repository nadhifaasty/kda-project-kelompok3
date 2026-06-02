import json
import time
import os
from datetime import datetime

import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from benchmark import RESULTS_PATH, load_results, run_benchmark, save_results
from crypto_utils import encrypt_text, decrypt_text

# === KONFIGURASI HALAMAN ===
st.set_page_config(
    page_title="Secure Notes",
    page_icon="\U0001f512",
    layout="wide",
)

# === KONSTANTA ===
ENCRYPTED_FILE: str = "notes/note.enc"
VERSI_APP: str = "1.0.0"
DEBOUNCE_DETIK: float = 2.0

OPSI_ALGORITMA: dict = {
    "AES-128-GCM": {"key_length": 128, "tingkat": "Standar"},
    "AES-192-GCM": {"key_length": 192, "tingkat": "Tinggi"},
    "AES-256-GCM": {"key_length": 256, "tingkat": "Maksimum"},
}


# === CSS DARK MODE ===
st.markdown(
    """
<style>
    :root {
        --bg-primary: #0e1117;
        --bg-secondary: #161b22;
        --bg-card: #1c2128;
        --border: #30363d;
        --text-primary: #e6edf3;
        --text-secondary: #8b949e;
        --text-muted: #6e7681;
        --accent: #58a6ff;
        --accent-hover: #79c0ff;
        --green: #3fb950;
        --green-bg: rgba(63, 185, 80, 0.12);
        --green-border: rgba(63, 185, 80, 0.3);
        --amber: #d29922;
        --amber-bg: rgba(210, 153, 34, 0.12);
        --amber-border: rgba(210, 153, 34, 0.3);
        --red: #f85149;
        --red-bg: rgba(248, 81, 73, 0.12);
        --red-border: rgba(248, 81, 73, 0.3);
    }

    .stApp {
        background-color: var(--bg-primary);
    }

    .main-header {
        font-size: 1.75rem;
        font-weight: 700;
        color: var(--text-primary);
        margin-bottom: 0.15rem;
        letter-spacing: -0.3px;
    }
    .sub-header {
        font-size: 0.85rem;
        color: var(--text-secondary);
        margin-bottom: 1.25rem;
    }

    .status-badge {
        display: inline-block;
        padding: 0.3rem 0.85rem;
        border-radius: 20px;
        font-size: 0.8rem;
        font-weight: 500;
    }
    .status-saved {
        background-color: var(--green-bg);
        color: var(--green);
        border: 1px solid var(--green-border);
    }
    .status-saving {
        background-color: var(--amber-bg);
        color: var(--amber);
        border: 1px solid var(--amber-border);
    }
    .status-unsaved {
        background-color: var(--red-bg);
        color: var(--red);
        border: 1px solid var(--red-border);
    }

    .info-card {
        background-color: var(--bg-card);
        border-radius: 8px;
        padding: 0.65rem 1rem;
        margin-bottom: 0.6rem;
        border: 1px solid var(--border);
    }
    .info-card p {
        margin: 0;
    }
    .info-card .label {
        color: var(--text-muted);
        font-size: 0.7rem;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        margin-bottom: 2px;
    }
    .info-card .value {
        color: var(--text-primary);
        font-weight: 500;
        font-size: 0.88rem;
    }
    .info-card .value-muted {
        color: var(--text-secondary);
        font-weight: 400;
        font-size: 0.82rem;
    }

    .security-level {
        display: flex;
        align-items: center;
        gap: 8px;
        padding: 0.5rem 0.85rem;
        border-radius: 6px;
        font-size: 0.8rem;
        font-weight: 500;
        margin-bottom: 0.6rem;
    }
    .security-standar {
        background-color: var(--green-bg);
        color: var(--green);
        border: 1px solid var(--green-border);
    }
    .security-tinggi {
        background-color: var(--amber-bg);
        color: var(--amber);
        border: 1px solid var(--amber-border);
    }
    .security-maksimum {
        background-color: rgba(88, 166, 255, 0.12);
        color: var(--accent);
        border: 1px solid rgba(88, 166, 255, 0.3);
    }

    .sidebar-title {
        font-size: 1.1rem;
        font-weight: 600;
        color: var(--text-primary);
        margin-bottom: 0.75rem;
    }
    .sidebar-divider {
        margin: 0.75rem 0;
        border: 0;
        height: 1px;
        background: var(--border);
    }
    .footer-text {
        font-size: 0.7rem;
        color: var(--text-muted);
        text-align: center;
        margin-top: 2rem;
    }

    .stTextArea textarea {
        background-color: var(--bg-secondary) !important;
        color: var(--text-primary) !important;
        border: 1px solid var(--border) !important;
        border-radius: 8px !important;
        font-size: 0.9rem !important;
        line-height: 1.6 !important;
        transition: border-color 0.2s ease;
    }
    .stTextArea textarea:focus {
        border-color: var(--accent) !important;
        box-shadow: 0 0 0 2px rgba(88, 166, 255, 0.15) !important;
    }
    .stTextArea textarea::placeholder {
        color: var(--text-muted) !important;
        opacity: 0.7;
    }

    .stButton button {
        border-radius: 6px !important;
        font-weight: 500 !important;
        font-size: 0.82rem !important;
    }
    .stButton button[kind="primary"] {
        background-color: var(--accent) !important;
        border: 1px solid var(--accent) !important;
        color: #ffffff !important;
    }
    .stButton button[kind="primary"]:hover {
        background-color: var(--accent-hover) !important;
        border-color: var(--accent-hover) !important;
    }

    section[data-testid="stSidebar"] {
        background-color: var(--bg-secondary);
        border-right: 1px solid var(--border);
    }
    section[data-testid="stSidebar"] .stButton button {
        width: 100%;
    }

    .stSelectbox label, .stSelectbox div[data-baseweb="select"] span {
        color: var(--text-secondary) !important;
    }
    .stSelectbox div[data-baseweb="select"] {
        background-color: var(--bg-card) !important;
        border-color: var(--border) !important;
    }
    .stSelectbox div[data-baseweb="select"]:hover {
        border-color: var(--accent) !important;
    }

    .char-counter {
        text-align: right;
        font-size: 0.75rem;
        color: var(--text-muted);
        margin-top: 0.25rem;
        padding-right: 0.25rem;
    }
</style>
""",
    unsafe_allow_html=True,
)


# === INISIALISASI SESSION STATE ===
def inisialisasi_session_state() -> None:
    """Menginisialisasi semua session state yang diperlukan aplikasi."""
    defaults: dict = {
        "teks_saat_ini": "",
        "teks_tersimpan": "",
        "waktu_ketik_terakhir": 0.0,
        "status_simpan": "tersimpan",
        "waktu_simpan": None,
        "catatan_pernah_dimuat": False,
        "algoritma_dipilih": "AES-256-GCM",
    }
    for key, val in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = val


inisialisasi_session_state()


# === FUNGSI BANTU ===
def _simpan_catatan(teks: str) -> None:
    """Menyimpan catatan ke file setelah dienkripsi."""
    try:
        ciphertext: str = encrypt_text(teks)
        os.makedirs("notes", exist_ok=True)
        with open(ENCRYPTED_FILE, "w", encoding="utf-8") as f:
            f.write(ciphertext)
        st.session_state["teks_tersimpan"] = teks
        st.session_state["waktu_simpan"] = datetime.now()
        st.session_state["status_simpan"] = "tersimpan"
    except Exception as e:
        st.error(f"Gagal menyimpan catatan: {e}")
        st.session_state["status_simpan"] = "belum_simpan"


def _muat_catatan() -> None:
    """Memuat catatan dari file dan mendekripsinya."""
    if not os.path.exists(ENCRYPTED_FILE):
        return
    try:
        with open(ENCRYPTED_FILE, "r", encoding="utf-8") as f:
            ciphertext: str = f.read()
        if not ciphertext.strip():
            return
        plaintext: str = decrypt_text(ciphertext)
        st.session_state["teks_saat_ini"] = plaintext
        st.session_state["teks_tersimpan"] = plaintext
        st.session_state["status_simpan"] = "tersimpan"
        st.session_state["waktu_simpan"] = datetime.now()
    except Exception as e:
        st.error(f"Gagal memuat catatan: {e}")


def _reset_catatan() -> None:
    """Mereset textarea dan session state ke kondisi awal."""
    st.session_state["teks_saat_ini"] = ""
    st.session_state["teks_tersimpan"] = ""
    st.session_state["status_simpan"] = "tersimpan"
    st.session_state["waktu_simpan"] = None


def _hapus_catatan() -> None:
    """Menghapus file catatan dan mereset state."""
    try:
        if os.path.exists(ENCRYPTED_FILE):
            os.remove(ENCRYPTED_FILE)
        _reset_catatan()
    except Exception as e:
        st.error(f"Gagal menghapus catatan: {e}")


def _format_ukuran(ukuran_bytes: int) -> str:
    """Memformat ukuran file dalam satuan yang mudah dibaca."""
    if ukuran_bytes < 1024:
        return f"{ukuran_bytes} B"
    elif ukuran_bytes < 1024 * 1024:
        return f"{ukuran_bytes / 1024:.1f} KB"
    else:
        return f"{ukuran_bytes / (1024 * 1024):.1f} MB"


# === LOAD CATATAN SAAT STARTUP ===
if not st.session_state["catatan_pernah_dimuat"]:
    st.session_state["catatan_pernah_dimuat"] = True
    _muat_catatan()


# === ANTARMUKA PENGGUNA ===

# --- SIDEBAR ---
with st.sidebar:
    st.markdown('<div class="sidebar-title">Pengaturan</div>', unsafe_allow_html=True)
    st.markdown('<hr class="sidebar-divider" />', unsafe_allow_html=True)

    # Pilihan algoritma
    algoritma_terpilih: str = st.selectbox(
        label="Algoritma Enkripsi",
        options=list(OPSI_ALGORITMA.keys()),
        key="algoritma_dipilih",
    )

    info_algo = OPSI_ALGORITMA[algoritma_terpilih]

    # Security level badge
    tingkat = info_algo["tingkat"]
    if tingkat == "Standar":
        cls_level = "security-standar"
    elif tingkat == "Tinggi":
        cls_level = "security-tinggi"
    else:
        cls_level = "security-maksimum"

    dot_map = {"Standar": "\u25cf", "Tinggi": "\u25cf", "Maksimum": "\u25cf"}
    st.markdown(
        f'<div class="security-level {cls_level}">{dot_map[tingkat]} Keamanan {tingkat.lower()}</div>',
        unsafe_allow_html=True,
    )

    st.markdown(
        f"""
    <div class="info-card">
        <p class="label">File Aktif</p>
        <p class="value">note.enc</p>
    </div>
    """,
        unsafe_allow_html=True,
    )

    # Ukuran file terenkripsi
    ukuran_file: str = "-"
    if os.path.exists(ENCRYPTED_FILE):
        ukuran_bytes: int = os.path.getsize(ENCRYPTED_FILE)
        ukuran_file = _format_ukuran(ukuran_bytes)

    st.markdown(
        f"""
    <div class="info-card">
        <p class="label">Ukuran File Enkripsi</p>
        <p class="value">{ukuran_file}</p>
    </div>
    """,
        unsafe_allow_html=True,
    )

    # Informasi kunci
    st.markdown(
        f"""
    <div class="info-card">
        <p class="label">Panjang Kunci</p>
        <p class="value">{info_algo["key_length"]} bit</p>
    </div>
    <div class="info-card">
        <p class="label">Mode Enkripsi</p>
        <p class="value">GCM (Galois/Counter Mode)</p>
    </div>
    <div class="info-card">
        <p class="label">Versi Aplikasi</p>
        <p class="value">{VERSI_APP}</p>
    </div>
    """,
        unsafe_allow_html=True,
    )

    st.markdown('<hr class="sidebar-divider" />', unsafe_allow_html=True)

    if st.button("+ Buat Catatan Baru", use_container_width=True):
        _reset_catatan()
        st.rerun()

    st.markdown('<hr class="sidebar-divider" />', unsafe_allow_html=True)

    st.markdown(
        f"""
    <div class="info-card">
        <p class="label">Terakhir Disimpan</p>
        <p class="value">{st.session_state["waktu_simpan"].strftime("%d %b %Y, %H:%M:%S") if st.session_state["waktu_simpan"] is not None else "-"}</p>
    </div>
    """,
        unsafe_allow_html=True,
    )

    # Jumlah karakter catatan
    jml_karakter: int = len(st.session_state["teks_saat_ini"])
    st.markdown(
        f"""
    <div class="info-card">
        <p class="label">Jumlah Karakter</p>
        <p class="value">{jml_karakter:,}</p>
    </div>
    """,
        unsafe_allow_html=True,
    )

# --- TAB NAVIGASI ---
tab1, tab2 = st.tabs(["📝 Catatan", "📊 Benchmark"])

with tab1:
    st.markdown('<div class="main-header">Secure Notes</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="sub-header">Catatan terenkripsi yang aman disimpan di perangkat lokal anda</div>',
        unsafe_allow_html=True,
    )

    teks_dari_widget: str = st.text_area(
        label="Catatan",
        label_visibility="collapsed",
        value=st.session_state["teks_saat_ini"],
        height=320,
        placeholder="Tulis catatanmu di sini...",
        key="input_catatan",
    )

    st.markdown(
        f'<div class="char-counter">{len(teks_dari_widget):,} karakter</div>',
        unsafe_allow_html=True,
    )

    if teks_dari_widget != st.session_state["teks_saat_ini"]:
        st.session_state["teks_saat_ini"] = teks_dari_widget
        st.session_state["waktu_ketik_terakhir"] = time.time()
        if teks_dari_widget != st.session_state["teks_tersimpan"]:
            st.session_state["status_simpan"] = "belum_simpan"

    col_status, col_spacer, col_simpan, col_hapus = st.columns([2.5, 1, 1.2, 1.2])

    with col_status:
        if st.session_state["status_simpan"] == "tersimpan":
            st.markdown(
                '<span class="status-badge status-saved">Tersimpan</span>',
                unsafe_allow_html=True,
            )
        elif st.session_state["status_simpan"] == "menyimpan":
            st.markdown(
                '<span class="status-badge status-saving">Menyimpan...</span>',
                unsafe_allow_html=True,
            )
        elif st.session_state["status_simpan"] == "belum_simpan":
            st.markdown(
                '<span class="status-badge status-unsaved">Ada perubahan yang belum disimpan</span>',
                unsafe_allow_html=True,
            )

    with col_simpan:
        if st.button("Simpan Sekarang", use_container_width=True, type="primary"):
            _simpan_catatan(st.session_state["teks_saat_ini"])
            st.rerun()

    with col_hapus:
        if st.button("Hapus Catatan", use_container_width=True):
            _hapus_catatan()
            st.rerun()

    st.markdown(
        '<div class="footer-text">Secure Notes -- Keamanan Data -- 2026</div>',
        unsafe_allow_html=True,
    )

    if st.session_state["status_simpan"] == "belum_simpan":
        waktu_sekarang: float = time.time()
        if waktu_sekarang - st.session_state["waktu_ketik_terakhir"] >= DEBOUNCE_DETIK:
            st.session_state["status_simpan"] = "menyimpan"
            _simpan_catatan(st.session_state["teks_saat_ini"])
            st.rerun()

with tab2:
    st.markdown('<div class="main-header">Benchmark AES-GCM</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="sub-header">Perbandingan performa AES-128, AES-192, dan AES-256 GCM</div>',
        unsafe_allow_html=True,
    )

    col_run, col_del = st.columns([2, 1])
    with col_run:
        if st.button("🚀 Jalankan Benchmark", type="primary", use_container_width=True):
            with st.spinner("Menjalankan benchmark... ini bisa memakan waktu beberapa saat."):
                results = run_benchmark()
                save_results(results)
                st.rerun()

    with col_del:
        if st.button("🗑 Hapus Hasil", use_container_width=True):
            if os.path.exists(RESULTS_PATH):
                os.remove(RESULTS_PATH)
                st.rerun()

    results = load_results()
    if results:
        df = []
        for r in results:
            df.append({
                "Algoritma": r["algo"],
                "Ukuran": r["size_label"],
                "Enc Rata-rata (ms)": r["enc_avg_ms"],
                "Dec Rata-rata (ms)": r["dec_avg_ms"],
                "Throughput (MB/s)": r["throughput_mbps"],
            })

        st.markdown("### Tabel Hasil")
        st.dataframe(df, hide_index=True, use_container_width=True)

        st.markdown("### Throughput per Algoritma")
        fig1 = px.bar(
            df,
            x="Ukuran",
            y="Throughput (MB/s)",
            color="Algoritma",
            barmode="group",
            text_auto=".1f",
            color_discrete_map={
                "AES-128": "#3fb950",
                "AES-192": "#d29922",
                "AES-256": "#58a6ff",
            },
        )
        fig1.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font_color="#e6edf3",
            height=400,
        )
        fig1.update_xaxes(gridcolor="#30363d")
        fig1.update_yaxes(gridcolor="#30363d")
        st.plotly_chart(fig1, use_container_width=True)

        st.markdown("### Waktu Enkripsi vs Ukuran Data")
        fig2 = px.line(
            df,
            x="Ukuran",
            y="Enc Rata-rata (ms)",
            color="Algoritma",
            markers=True,
            color_discrete_map={
                "AES-128": "#3fb950",
                "AES-192": "#d29922",
                "AES-256": "#58a6ff",
            },
        )
        fig2.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font_color="#e6edf3",
            height=400,
        )
        fig2.update_xaxes(gridcolor="#30363d")
        fig2.update_yaxes(gridcolor="#30363d")
        st.plotly_chart(fig2, use_container_width=True)

        st.markdown("### Waktu Dekripsi vs Ukuran Data")
        fig3 = px.line(
            df,
            x="Ukuran",
            y="Dec Rata-rata (ms)",
            color="Algoritma",
            markers=True,
            color_discrete_map={
                "AES-128": "#3fb950",
                "AES-192": "#d29922",
                "AES-256": "#58a6ff",
            },
        )
        fig3.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font_color="#e6edf3",
            height=400,
        )
        fig3.update_xaxes(gridcolor="#30363d")
        fig3.update_yaxes(gridcolor="#30363d")
        st.plotly_chart(fig3, use_container_width=True)

    else:
        st.info("Belum ada data benchmark. Klik tombol **🚀 Jalankan Benchmark** di atas untuk memulai.")
