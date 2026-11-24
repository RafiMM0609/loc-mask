# PII-Shield

Server masking lokal berbasis Python (**Microsoft Presidio + Secret Pattern Recognizers**) yang berjalan di `http://127.0.0.1:8787` untuk melindungi **Antigravity**, **Codex CLI**, dan **Pi dev CLI** dari kebocoran secrets maupun data pribadi (PII).

## Fitur Utama

1. **Hybrid Protection:**
   - **Codex CLI & Pi dev CLI:** Auto-Masking & Unmasking **2 arah** (`nilai asli` -> `<<PII:TYPE_N>>` -> `nilai asli`) termasuk dukungan **SSE streaming** agar output AI tetap relevan tanpa mengirim rahasia asli ke cloud.
   - **Antigravity:** **Safety Gate** (`PreInvocation` hook) yang langsung memblokir pengiriman jika terdeteksi data sensitif di prompt, dengan fallback offline pure-regex jika server sedang mati.
2. **Deteksi Default:**
   - **Secrets:** OpenAI, Anthropic, Google, AWS, GitHub, GitLab, Slack, Stripe, Telegram, Midtrans, Xendit, npm/PyPI/HF token, JWT, Bearer/Basic token, DB connection URI (`postgres://`, `mysql://`, `mongodb://`, dll.), PEM Private Key, serta assignment `password`/`secret`/`token` (kecuali dummy allowlist).
   - **PII Utama:** NIK 16 digit Indonesia, Nomor HP Indonesia (`08...`/`+628...`), Email, Kartu Kredit (Luhn check).
   - **Konteks Koding Aman:** Nama orang (`PERSON`), lokasi, dan IP lokal (`localhost`, `192.168.x.x`, `10.x.x.x`) **tidak** dimasking secara default.
3. **Zero Disk Leak:** Mapping vault 2 arah hanya disimpan di memori RAM selama server berjalan.

---

## Cara Menjalankan Server (Manual)

```cmd
cd ~/pii-shield

:: Jalankan di background
pii-shield.cmd start

:: Cek status server
pii-shield.cmd status

:: Uji masking & unmasking
pii-shield.cmd test "API key saya sk-proj-abc123456789012345678901 dan NIK 3273011508950001"

:: Hentikan server
pii-shield.cmd stop
```

Atau klik ganda `start-server.cmd` / `stop-server.cmd`.

---

## Integrasi ke Agent (Siap Review di Folder `connectors/`)

**Belum ada konfigurasi aktif yang diubah.** Anda bisa meninjau file di `connectors/` terlebih dahulu:

- **Antigravity:** `connectors/antigravity/antigravity_guard.py` & `hooks.example.json`
- **Codex CLI:** `connectors/codex/config.example.toml` (menggunakan `chatgpt_base_url = "http://127.0.0.1:8787/chatgpt-backend/"` untuk mode login ChatGPT Anda)
- **Pi dev CLI:** `connectors/pi/pii-shield.ts` (TypeScript Extension untuk `~/.pi/agent/extensions/pii-shield.ts`, bekerja di semua provider termasuk `opencode-go`)

### Mengaktifkan Secara Otomatis (Setelah Anda Review)

```cmd
:: Cek status saat ini
.venv\Scripts\python.exe connectors\install_connectors.py --status

:: Simulasi dulu tanpa mengubah file
.venv\Scripts\python.exe connectors\install_connectors.py --apply all --dry-run

:: Pasang semua (otomatis membuat backup .bak sebelum mengubah config)
.venv\Scripts\python.exe connectors\install_connectors.py --apply all

:: Jika ingin batal / kembali ke config awal:
.venv\Scripts\python.exe connectors\install_connectors.py --rollback
```
