# PII-Shield

Server masking lokal Python (**Microsoft Presidio + Secret Pattern Recognizers**) di `http://127.0.0.1:8787` untuk melindungi **Antigravity (`agy`)**, **T3 Code**, **Codex CLI**, dan **Pi dev CLI** dari kebocoran secrets & PII.

## Mekanisme Proteksi

- **Antigravity (`agy`) & T3 Code:**
  - **`PreInvocation` Safety Gate** (`antigravity_guard.py`): Memblokir prompt user jika mengandung secret/PII (otomatis *fallback* ke regex offline jika server mati).
  - **`PreToolUse` Tool Guard** (`antigravity_tool_guard.py` + `run_command_mask_wrapper.py`): Memasking `stdout`/`stderr` dari `run_command` sebelum masuk ke model, serta memblokir `read_file`/`view_file`/`view_file_outline`/`view_code_item` dan `grep_search` pada file sensitif (`.env`, `*.pem`, `*.key`, `credentials.json`, dll.) maupun file config/data/log yang terdeteksi mengandung secret/PII agar dibaca lewat `run_command`.
- **Codex CLI:** Hook native memeriksa prompt pengguna dan menyamarkan output shell. Jika PS menemukan data sensitif di prompt, samarkan data itu lalu kirim ulang.
- **Pi dev CLI:** Extension `pii-shield.ts` mendukung masking dan unmasking 2 arah (`nilai asli` ↔ `<<PII:TYPE_N>>`).
- **Zero Disk Leak & Konteks Aman:** Vault 2 arah hanya disimpan di RAM; `PERSON`, `LOCATION`, dan IP lokal tidak dimasking secara default.

---

## Menjalankan Server

```cmd
cd ~/pii-shield

pii-shield.cmd start    :: Jalankan server di background
pii-shield.cmd status   :: Cek status & jumlah placeholder aktif
pii-shield.cmd test "API key sk-proj-abc123456789012345678901 dan NIK 3273011508950001"
pii-shield.cmd stop     :: Hentikan server
```

Atau klik ganda `start-server.cmd` / `stop-server.cmd`.

---

## Cara Pakai per Tool

```cmd
:: Cek status instalasi connector
.venv\Scripts\python.exe connectors\install_connectors.py --status

:: Simulasi tanpa mengubah config
.venv\Scripts\python.exe connectors\install_connectors.py --apply all --dry-run
```

### 1. Antigravity (`agy`) & T3 Code
```cmd
.venv\Scripts\python.exe connectors\install_connectors.py --apply antigravity
```
Installer memasang hook PS di `~/.gemini/config/hooks.json` untuk Antigravity standalone dan di `~/.t3/userdata/providers/antigravity/<profile-id>/config/hooks.json` untuk setiap profil Antigravity yang sudah ada di T3 Code. Setiap profil punya file sendiri. Installer mempertahankan entri lain dan membuat backup `.bak.*` jika file yang sudah ada perlu diperbarui.

Jalankan kembali `--apply antigravity` setelah menambahkan profil Antigravity baru di T3 Code. Gunakan `--status` untuk mengecek pemasangan per profil, lalu buka thread baru di profil itu agar T3 Code memuat hook.

- **Prompt sensitif** langsung diblokir sebelum dikirim ke model.
- **Output `run_command`** otomatis dimasking (`<<PII:...>>`).
- **Akses baca/cari `.env`, file kunci, maupun config/data/log berisi secret/PII** lewat `read_file`/`view_file`/`grep_search` otomatis ditolak dan diarahkan agar memakai `run_command`.

### 2. Codex CLI & Pi dev CLI
```cmd
.venv\Scripts\python.exe connectors\install_connectors.py --apply codex
.venv\Scripts\python.exe connectors\install_connectors.py --apply pi
:: atau pasang semua sekaligus:
.venv\Scripts\python.exe connectors\install_connectors.py --apply all
```
Installer Codex memasang `UserPromptSubmit` dan `PostToolUse` di `$CODEX_HOME/hooks.json` (default `~/.codex/hooks.json`). Buka sesi baru dan tinjau serta percayai kedua hook di `/hooks`. Login dan provider mengikuti konfigurasi Codex.

- `UserPromptSubmit` memeriksa teks prompt lewat server PS lokal. Saat server tidak tersedia, hook memakai regex offline. Pesan blokir berisi jenis temuan agar pengguna bisa menyamarkan teks dan mengirim ulang.
- `PostToolUse` memeriksa hasil shell yang diberikan Codex. Jika hasil memuat data sensitif, hook menggantinya dengan teks yang sudah disamarkan. Codex menjalankan command asli dengan kebijakan sandbox dan approval sesi.

Cakupan kedua hook ini terbatas pada teks prompt pengguna dan hasil shell yang diterima `PostToolUse`. Output parsial yang dilepas saat command masih berjalan, lampiran, riwayat lokal, dan hasil tool lain berada di luar cakupan.

Untuk instalasi proxy lama, jalankan `--apply codex --dry-run` terlebih dahulu. Installer menghapus blok proxy milik PS dan memulihkan pilihan provider jika backup yang cocok menghasilkan satu pilihan. Jika pilihan lama ambigu, tentukan `model_provider` di `config.toml` atau hapus selector agar Codex memakai default, lalu ulangi.

### Rollback
```cmd
.venv\Scripts\python.exe connectors\install_connectors.py --rollback
.venv\Scripts\python.exe connectors\install_connectors.py --rollback codex
```

Rollback Codex memakai snapshot sebelum pemasangan. Jika file terkait disunting setelah pemasangan, installer melindungi perubahan tersebut dan menunjukkan lokasi backup untuk pemulihan manual.
