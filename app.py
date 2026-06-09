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
    page_icon="🔒",
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


# === CSS SOFT PASTEL ===
st.markdown(
    """
<style>
    @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap');

    html, body, [data-testid="stAppViewContainer"], [data-testid="stSidebar"], .stApp, 
    .stButton button, .stTextArea textarea, .stSelectbox div[data-baseweb="select"], 
    button[data-baseweb="tab"], label, input, select {
        font-family: 'Plus Jakarta Sans', sans-serif !important;
    }

    /* Restore Material Symbols/Icons font-family to prevent icons from rendering as raw text */
    .material-icons, 
    .material-symbols-outlined, 
    [data-testid="stIconMaterial"] {
        font-family: 'Material Symbols Outlined', 'Material Symbols Rounded', 'Material Symbols Sharp', 'Material Icons' !important;
    }

    /* Ensure markdown text and headings are dark charcoal for contrast on the light background */
    .stMarkdown h1, .stMarkdown h2, .stMarkdown h3, .stMarkdown h4, .stMarkdown h5, .stMarkdown h6,
    .stMarkdown p, .stMarkdown li, [data-testid="stMarkdownContainer"] h1, [data-testid="stMarkdownContainer"] h2,
    [data-testid="stMarkdownContainer"] h3, [data-testid="stMarkdownContainer"] h4, [data-testid="stMarkdownContainer"] h5,
    [data-testid="stMarkdownContainer"] h6, [data-testid="stMarkdownContainer"] p, [data-testid="stMarkdownContainer"] li,
    .main h1, .main h2, .main h3, .main h4, .main h5, .main h6,
    .main p, .main label, .main li {
        color: #221E1F !important;
    }

    :root {
        --bg-primary: #FAF6ED;      /* Soft warm cream-beige */
        --bg-secondary: #EFEAE0;    /* Muted warm beige for tabs/containers */
        --bg-card: #FFFFFF;         /* White background for notes textarea & main panels */
        --border: rgba(34, 30, 31, 0.08); /* Soft dark-grey border */
        --text-primary: #221E1F;    /* Charcoal black for primary readability */
        --text-secondary: #6B6869;  /* Soft grey for subtext */
        --text-muted: #9F9D9E;      /* Muted grey */
        --accent: #221E1F;          /* Solid dark accent for buttons */
        --accent-hover: #413D3E;    /* Dark charcoal for button hover */
        
        /* Card colors matching the intelly theme closely */
        --card-blue-bg: #C9D9EB;
        --card-blue-text: #1C355E;
        --card-blue-border: rgba(28, 53, 94, 0.15);
        
        --card-pink-bg: #F7C8D8;
        --card-pink-text: #5E162C;
        --card-pink-border: rgba(94, 22, 44, 0.15);
        
        --card-yellow-bg: #FCDA8F;
        --card-yellow-text: #5C3E08;
        --card-yellow-border: rgba(92, 62, 8, 0.15);
        
        --card-green-bg: #B8D6BC;
        --card-green-text: #1D4222;
        --card-green-border: rgba(29, 66, 34, 0.15);
        
        --card-purple-bg: #DFCAE6;
        --card-purple-text: #441C4F;
        --card-purple-border: rgba(68, 28, 79, 0.15);

        --shadow-glass: 0 4px 12px rgba(34, 30, 31, 0.02);
        --shadow-hover: 0 8px 24px rgba(34, 30, 31, 0.05);
    }

    .stApp {
        background-color: var(--bg-primary) !important;
    }

    .block-container {
        padding-top: 4.5rem !important;
    }

    .main > div {
        background: transparent;
    }

    .stAlert {
        background: #FFFFFF !important;
        border: 1px solid var(--border) !important;
        border-left: 4px solid #221E1F !important;
        border-radius: 16px !important;
        color: var(--text-primary) !important;
        box-shadow: 0 4px 16px rgba(0, 0, 0, 0.02) !important;
    }
    .stAlert p {
        color: var(--text-secondary) !important;
    }

    ::-webkit-scrollbar {
        width: 6px;
        height: 6px;
    }
    ::-webkit-scrollbar-track {
        background: var(--bg-primary);
    }
    ::-webkit-scrollbar-thumb {
        background: rgba(34, 30, 31, 0.1);
        border-radius: 3px;
    }
    ::-webkit-scrollbar-thumb:hover {
        background: rgba(34, 30, 31, 0.2);
    }

    .stDataFrame {
        border-radius: 16px !important;
        overflow: hidden !important;
        border: 1px solid #EFEAE0 !important;
        box-shadow: 0 4px 16px rgba(0, 0, 0, 0.02) !important;
    }
    .stDataFrame thead tr th {
        background-color: #EFEAE0 !important;
        color: var(--text-primary) !important;
        font-weight: 700 !important;
        padding: 0.75rem 1rem !important;
    }
    .stDataFrame tbody tr td {
        background-color: var(--bg-card) !important;
        color: var(--text-primary) !important;
        padding: 0.65rem 1rem !important;
    }
    .stDataFrame tbody tr:hover td {
        background-color: rgba(34, 30, 31, 0.02) !important;
    }

    .glass-card {
        background: var(--bg-card);
        border: 1px solid var(--border);
        border-radius: 16px;
        padding: 1rem 1.25rem;
        margin-bottom: 0.75rem;
        box-shadow: var(--shadow-glass);
        transition: all 0.3s ease;
    }
    .glass-card:hover {
        box-shadow: var(--shadow-hover);
        transform: translateY(-2px);
    }

    .main-header {
        font-size: 2.25rem !important;
        font-weight: 800 !important;
        color: var(--text-primary) !important;
        margin-bottom: 0.35rem !important;
        letter-spacing: -0.8px !important;
        line-height: 1.2 !important;
    }
    .sub-header {
        font-size: 0.95rem !important;
        color: var(--text-secondary) !important;
        margin-bottom: 1.5rem !important;
        font-weight: 400 !important;
    }

    .status-badge {
        display: inline-flex;
        align-items: center;
        padding: 0.5rem 1.25rem;
        border-radius: 100px;
        font-size: 0.85rem;
        font-weight: 600;
        letter-spacing: 0.3px;
        transition: all 0.3s ease;
    }
    .status-saved {
        background: var(--card-green-bg) !important;
        color: var(--card-green-text) !important;
        border: 1px solid var(--card-green-border) !important;
    }
    .status-saving {
        background: var(--card-yellow-bg) !important;
        color: var(--card-yellow-text) !important;
        border: 1px solid var(--card-yellow-border) !important;
        animation: pulse 1.5s ease-in-out infinite;
    }

    @keyframes pulse {
        0%, 100% { opacity: 1; }
        50% { opacity: 0.6; }
    }
    .status-unsaved {
        background: var(--card-pink-bg) !important;
        color: var(--card-pink-text) !important;
        border: 1px solid var(--card-pink-border) !important;
    }

    .info-card {
        backdrop-filter: blur(12px);
        border-radius: 18px !important;
        padding: 0.85rem 1.1rem !important;
        margin-bottom: 0.75rem !important;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.02) !important;
        transition: all 0.3s ease !important;
        border: 1px solid var(--border) !important;
    }
    .info-card:hover {
        transform: translateY(-2px) !important;
        box-shadow: 0 8px 20px rgba(0, 0, 0, 0.05) !important;
    }
    .info-card p {
        margin: 0 !important;
    }
    .info-card .label {
        font-size: 0.75rem !important;
        text-transform: uppercase;
        letter-spacing: 0.7px;
        margin-bottom: 4px !important;
        font-weight: 600 !important;
    }
    .info-card .value {
        font-weight: 700 !important;
        font-size: 1rem !important;
    }
    .info-card .value-muted {
        font-weight: 500;
        font-size: 0.85rem;
    }

    .info-card-blue {
        background: var(--card-blue-bg) !important;
        border-color: var(--card-blue-border) !important;
    }
    .info-card-blue .label {
        color: rgba(28, 53, 94, 0.6) !important;
    }
    .info-card-blue .value {
        color: var(--card-blue-text) !important;
    }
    
    .info-card-pink {
        background: var(--card-pink-bg) !important;
        border-color: var(--card-pink-border) !important;
    }
    .info-card-pink .label {
        color: rgba(94, 22, 44, 0.6) !important;
    }
    .info-card-pink .value {
        color: var(--card-pink-text) !important;
    }
    
    .info-card-yellow {
        background: var(--card-yellow-bg) !important;
        border-color: var(--card-yellow-border) !important;
    }
    .info-card-yellow .label {
        color: rgba(92, 62, 8, 0.6) !important;
    }
    .info-card-yellow .value {
        color: var(--card-yellow-text) !important;
    }
    
    .info-card-green {
        background: var(--card-green-bg) !important;
        border-color: var(--card-green-border) !important;
    }
    .info-card-green .label {
        color: rgba(29, 66, 34, 0.6) !important;
    }
    .info-card-green .value {
        color: var(--card-green-text) !important;
    }
    
    .info-card-purple {
        background: var(--card-purple-bg) !important;
        border-color: var(--card-purple-border) !important;
    }
    .info-card-purple .label {
        color: rgba(68, 28, 79, 0.6) !important;
    }
    .info-card-purple .value {
        color: var(--card-purple-text) !important;
    }

    .security-level {
        display: flex;
        align-items: center;
        gap: 8px;
        padding: 0.6rem 1rem;
        border-radius: 12px;
        font-size: 0.85rem;
        font-weight: 600;
        margin-bottom: 0.75rem;
        transition: all 0.3s ease;
    }
    .security-standar {
        background: var(--card-green-bg) !important;
        color: var(--card-green-text) !important;
        border: 1px solid var(--card-green-border) !important;
    }
    .security-standar:hover {
        background: rgba(29, 66, 34, 0.15) !important;
        transform: translateY(-1px);
    }
    .security-tinggi {
        background: var(--card-yellow-bg) !important;
        color: var(--card-yellow-text) !important;
        border: 1px solid var(--card-yellow-border) !important;
    }
    .security-tinggi:hover {
        background: rgba(92, 62, 8, 0.15) !important;
        transform: translateY(-1px);
    }
    .security-maksimum {
        background: var(--card-pink-bg) !important;
        color: var(--card-pink-text) !important;
        border: 1px solid var(--card-pink-border) !important;
    }
    .security-maksimum:hover {
        background: rgba(94, 22, 44, 0.15) !important;
        transform: translateY(-1px);
    }

    .sidebar-title {
        font-size: 1.25rem !important;
        font-weight: 700 !important;
        color: #FFFFFF !important;
        margin-bottom: 0.75rem;
    }
    .sidebar-divider {
        margin: 1rem 0 !important;
        border: 0 !important;
        height: 1px !important;
        background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.15), transparent) !important;
    }
    .footer-text {
        font-size: 0.8rem;
        color: var(--text-muted);
        text-align: center;
        margin-top: 2rem;
        transition: color 0.25s ease;
    }
    .footer-text:hover {
        color: var(--text-secondary);
    }

    div[data-baseweb="tab-list"] {
        gap: 8px !important;
        background: #EFEAE0 !important;
        border-radius: 100px !important;
        padding: 6px !important;
        border: none !important;
    }
    button[data-baseweb="tab"] {
        border-radius: 100px !important;
        color: var(--text-secondary) !important;
        font-weight: 600 !important;
        font-size: 0.88rem !important;
        transition: all 0.3s ease !important;
        padding: 0.6rem 1.5rem !important;
        border: none !important;
        background: transparent !important;
    }
    button[data-baseweb="tab"] span,
    button[data-baseweb="tab"] p {
        color: var(--text-secondary) !important;
    }
    button[data-baseweb="tab"]:hover {
        color: var(--text-primary) !important;
    }
    button[data-baseweb="tab"]:hover span,
    button[data-baseweb="tab"]:hover p {
        color: var(--text-primary) !important;
    }
    button[data-baseweb="tab"][aria-selected="true"] {
        color: #FFFFFF !important;
        background: #221E1F !important;
        box-shadow: 0 4px 12px rgba(34, 30, 31, 0.15) !important;
        border: none !important;
    }
    button[data-baseweb="tab"][aria-selected="true"] span,
    button[data-baseweb="tab"][aria-selected="true"] p {
        color: #FFFFFF !important;
    }
    div[data-baseweb="tab-highlight"] {
        display: none !important;
    }

    .stTextArea textarea {
        background: #FFFFFF !important;
        color: var(--text-primary) !important;
        border: 2px solid #EFEAE0 !important;
        border-radius: 20px !important;
        font-size: 1rem !important;
        line-height: 1.7 !important;
        transition: all 0.3s ease !important;
        padding: 1.25rem !important;
        box-shadow: 0 4px 16px rgba(34, 30, 31, 0.02) !important;
    }
    .stTextArea textarea:focus {
        border-color: #221E1F !important;
        box-shadow: 0 0 0 4px rgba(34, 30, 31, 0.08), 0 8px 24px rgba(34, 30, 31, 0.04) !important;
        background: #FFFFFF !important;
    }
    .stTextArea textarea::placeholder {
        color: var(--text-muted) !important;
        opacity: 0.6;
    }
    .stTextArea textarea:hover {
        border-color: #D3C9B6 !important;
    }

    .stButton button {
        border-radius: 100px !important;
        font-weight: 600 !important;
        font-size: 0.9rem !important;
        transition: all 0.3s ease !important;
        padding: 0.5rem 1.2rem !important;
        border: none !important;
        white-space: nowrap !important;
        width: 100% !important;
    }
    .stButton button[kind="primary"] {
        background: #221E1F !important;
        color: #FFFFFF !important;
        box-shadow: 0 4px 12px rgba(34, 30, 31, 0.12) !important;
    }
    .stButton button[kind="primary"] span,
    .stButton button[kind="primary"] p {
        color: #FFFFFF !important;
    }
    .stButton button[kind="primary"]:hover {
        background: #413D3E !important;
        box-shadow: 0 8px 20px rgba(34, 30, 31, 0.2) !important;
        transform: translateY(-2px) !important;
    }
    .stButton button[kind="primary"]:hover span,
    .stButton button[kind="primary"]:hover p {
        color: #FFFFFF !important;
    }
    .stButton button:not([kind="primary"]) {
        background: #EFEAE0 !important;
        color: #221E1F !important;
        border: 1px solid #E3DDD2 !important;
    }
    .stButton button:not([kind="primary"]) span,
    .stButton button:not([kind="primary"]) p {
        color: #221E1F !important;
    }
    .stButton button:not([kind="primary"]):hover {
        background: #FAF6ED !important;
        border-color: #221E1F !important;
        color: #221E1F !important;
        transform: translateY(-2px) !important;
        box-shadow: 0 4px 12px rgba(34, 30, 31, 0.05) !important;
    }
    .stButton button:not([kind="primary"]):hover span,
    .stButton button:not([kind="primary"]):hover p {
        color: #221E1F !important;
    }

    section[data-testid="stSidebar"] {
        background-color: #1E1B1C !important;
        border-right: none !important;
    }
    @media (min-width: 768px) {
        section[data-testid="stSidebar"] {
            border-top-right-radius: 24px !important;
            border-bottom-right-radius: 24px !important;
            overflow: hidden !important;
        }
    }
    section[data-testid="stSidebar"] .stMarkdown, 
    section[data-testid="stSidebar"] .stMarkdown h1,
    section[data-testid="stSidebar"] .stMarkdown h2,
    section[data-testid="stSidebar"] .stMarkdown h3,
    section[data-testid="stSidebar"] .stMarkdown h4,
    section[data-testid="stSidebar"] .stMarkdown h5,
    section[data-testid="stSidebar"] .stMarkdown h6,
    section[data-testid="stSidebar"] .stMarkdown p,
    section[data-testid="stSidebar"] .stMarkdown li,
    section[data-testid="stSidebar"] label,
    section[data-testid="stSidebar"] p,
    section[data-testid="stSidebar"] span {
        color: #E5E2E0 !important;
    }
    section[data-testid="stSidebar"] div[data-baseweb="select"] {
        background: rgba(255, 255, 255, 0.07) !important;
        border: 1px solid rgba(255, 255, 255, 0.15) !important;
        border-radius: 12px !important;
    }
    section[data-testid="stSidebar"] div[data-baseweb="select"] span {
        color: #FFFFFF !important;
    }
    section[data-testid="stSidebar"] label {
        color: rgba(255, 255, 255, 0.6) !important;
        font-weight: 500 !important;
    }
    section[data-testid="stSidebar"] .stButton button {
        background-color: #EFEAE0 !important;
        color: #221E1F !important;
        border: none !important;
        border-radius: 100px !important;
        font-weight: 600 !important;
        padding: 0.6rem 1.5rem !important;
        transition: all 0.3s ease !important;
    }
    section[data-testid="stSidebar"] .stButton button span,
    section[data-testid="stSidebar"] .stButton button p {
        color: #221E1F !important;
    }
    section[data-testid="stSidebar"] .stButton button:hover {
        background-color: #FFFFFF !important;
        transform: translateY(-2px) !important;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.25) !important;
    }
    section[data-testid="stSidebar"] .stButton button:hover span,
    section[data-testid="stSidebar"] .stButton button:hover p {
        color: #221E1F !important;
    }

    section[data-testid="stSidebar"] .info-card {
        background: rgba(255, 255, 255, 0.04) !important;
        border: 1px solid rgba(255, 255, 255, 0.08) !important;
        border-radius: 14px !important;
        padding: 0.75rem 1rem !important;
        margin-bottom: 0.6rem !important;
        box-shadow: none !important;
        transition: all 0.3s ease !important;
    }
    section[data-testid="stSidebar"] .info-card:hover {
        background: rgba(255, 255, 255, 0.08) !important;
        transform: translateY(-1px) !important;
    }
    section[data-testid="stSidebar"] .info-card .label {
        color: rgba(255, 255, 255, 0.4) !important;
        font-size: 0.72rem !important;
        font-weight: 600 !important;
    }
    section[data-testid="stSidebar"] .info-card .value {
        color: #E5E2E0 !important;
        font-size: 0.92rem !important;
        font-weight: 600 !important;
    }

    .stSelectbox div[data-baseweb="select"] {
        background: #FFFFFF !important;
        border: 2px solid #EFEAE0 !important;
        border-radius: 14px !important;
        transition: all 0.25s ease;
        box-shadow: none !important;
    }
    .stSelectbox div[data-baseweb="select"]:hover {
        border-color: #D3C9B6 !important;
    }
    .stSelectbox div[data-baseweb="select"]:focus-within {
        border-color: #221E1F !important;
    }

    .char-counter {
        text-align: right;
        font-size: 0.85rem;
        color: var(--text-muted);
        margin-top: 0.35rem;
        padding-right: 0.25rem;
    }

    .stSpinner {
        color: #221E1F !important;
    }

    .st-emotion-cache-1mi2ry5, .st-emotion-cache-1dp5vir {
        background: transparent !important;
    }
</style>""",
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
    <div class="info-card info-card-blue">
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
    <div class="info-card info-card-pink">
        <p class="label">Ukuran File Enkripsi</p>
        <p class="value">{ukuran_file}</p>
    </div>
    """,
        unsafe_allow_html=True,
    )

    # Informasi kunci
    st.markdown(
        f"""
    <div class="info-card info-card-yellow">
        <p class="label">Panjang Kunci</p>
        <p class="value">{info_algo["key_length"]} bit</p>
    </div>
    <div class="info-card info-card-purple">
        <p class="label">Mode Enkripsi</p>
        <p class="value">GCM (Galois/Counter Mode)</p>
    </div>
    <div class="info-card info-card-blue">
        <p class="label">Versi Aplikasi</p>
        <p class="value">{VERSI_APP}</p>
    </div>
    """,
        unsafe_allow_html=True,
    )

    st.markdown('<hr class="sidebar-divider" />', unsafe_allow_html=True)

    if st.button("Buat Catatan Baru", use_container_width=True):
        _reset_catatan()
        st.rerun()

    st.markdown('<hr class="sidebar-divider" />', unsafe_allow_html=True)

    st.markdown(
        f"""
    <div class="info-card info-card-pink">
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
    <div class="info-card info-card-green">
        <p class="label">Jumlah Karakter</p>
        <p class="value">{jml_karakter:,}</p>
    </div>
    """,
        unsafe_allow_html=True,
    )

# --- TAB NAVIGASI ---
tab1, tab2 = st.tabs(["Catatan", "Benchmark"])

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

    col_status, col_spacer, col_simpan, col_hapus = st.columns([2, 0.4, 1.8, 1.8])

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
                '<span class="status-badge status-unsaved">Belum disimpan</span>',
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
        if st.button("Jalankan Benchmark", type="primary", use_container_width=True):
            with st.spinner("Menjalankan benchmark... ini bisa memakan waktu beberapa saat."):
                results = run_benchmark()
                save_results(results)
                st.rerun()

    with col_del:
        if st.button("Hapus Hasil", use_container_width=True):
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
                "AES-128": "#4A7BB0",
                "AES-192": "#D49A24",
                "AES-256": "#C46D8C",
            },
        )
        fig1.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font_color="#221E1F",
            height=400,
        )
        fig1.update_xaxes(
            showline=True,
            linecolor="rgba(34, 30, 31, 0.2)",
            gridcolor="rgba(34, 30, 31, 0.15)",
            gridwidth=0.5
        )
        fig1.update_yaxes(
            showline=True,
            linecolor="rgba(34, 30, 31, 0.2)",
            gridcolor="rgba(34, 30, 31, 0.15)",
            gridwidth=0.5
        )
        st.plotly_chart(fig1, use_container_width=True, theme=None)

        st.markdown("### Waktu Enkripsi vs Ukuran Data")
        fig2 = px.line(
            df,
            x="Ukuran",
            y="Enc Rata-rata (ms)",
            color="Algoritma",
            markers=True,
            color_discrete_map={
                "AES-128": "#4A7BB0",
                "AES-192": "#D49A24",
                "AES-256": "#C46D8C",
            },
        )
        fig2.update_traces(line=dict(width=3), marker=dict(size=8))
        fig2.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font_color="#221E1F",
            height=400,
        )
        fig2.update_xaxes(
            showline=True,
            linecolor="rgba(34, 30, 31, 0.2)",
            gridcolor="rgba(34, 30, 31, 0.15)",
            gridwidth=0.5
        )
        fig2.update_yaxes(
            showline=True,
            linecolor="rgba(34, 30, 31, 0.2)",
            gridcolor="rgba(34, 30, 31, 0.15)",
            gridwidth=0.5
        )
        st.plotly_chart(fig2, use_container_width=True, theme=None)

        st.markdown("### Waktu Dekripsi vs Ukuran Data")
        fig3 = px.line(
            df,
            x="Ukuran",
            y="Dec Rata-rata (ms)",
            color="Algoritma",
            markers=True,
            color_discrete_map={
                "AES-128": "#4A7BB0",
                "AES-192": "#D49A24",
                "AES-256": "#C46D8C",
            },
        )
        fig3.update_traces(line=dict(width=3), marker=dict(size=8))
        fig3.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font_color="#221E1F",
            height=400,
        )
        fig3.update_xaxes(
            showline=True,
            linecolor="rgba(34, 30, 31, 0.2)",
            gridcolor="rgba(34, 30, 31, 0.15)",
            gridwidth=0.5
        )
        fig3.update_yaxes(
            showline=True,
            linecolor="rgba(34, 30, 31, 0.2)",
            gridcolor="rgba(34, 30, 31, 0.15)",
            gridwidth=0.5
        )
        st.plotly_chart(fig3, use_container_width=True, theme=None)

    else:
        st.info("Belum ada data benchmark. Klik tombol **Jalankan Benchmark** di atas untuk memulai.")
