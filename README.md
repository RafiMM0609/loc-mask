# PII-Shield

Server masking lokal Python (**Microsoft Presidio + Secret Pattern Recognizers**) di `http://127.0.0.1:8787` untuk melindungi **Antigravity (`agy`)**, **T3 Code**, **Codex CLI**, dan **Pi dev CLI** dari kebocoran secrets & PII.

## Mekanisme Proteksi

- **Antigravity (`agy`) & T3 Code:**
  - **`PreInvocation` Safety Gate** (`antigravity_guard.py`): Memblokir prompt user jika mengandung secret/PII (otomatis *fallback* ke regex offline jika server mati).
  - **`PreToolUse` Tool Guard** (`antigravity_tool_guard.py` + `run_command_mask_wrapper.py`): Memasking `stdout`/`stderr` dari `run_command` sebelum masuk ke model, serta mengalihkan `read_file`/`view_file` atas file sensitif (`.env`, `*.pem`, `*.key`, `credentials.json`, dll.) agar dibaca lewat `run_command`.
- **Codex CLI & Pi dev CLI:**
  - **Auto-Mask & Unmask 2 Arah** (`nilai asli` ↔ `<<PII:TYPE_N>>`) lewat reverse proxy (`/chatgpt-backend/`, `/openai/`) dan extension Pi (`pii-shield.ts`), termasuk SSE streaming.
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
Perintah ini otomatis memasang `hooks.json` ke `~/.gemini/config/hooks.json` (`agy` CLI/IDE) dan seluruh provider Antigravity di T3 Code (`~/.t3/userdata/providers/antigravity/*/config/hooks.json`).
- **Prompt sensitif** langsung diblokir sebelum dikirim ke model.
- **Output `run_command`** otomatis dimasking (`<<PII:...>>`).
- **Akses baca `.env` / file kunci** lewat `read_file`/`view_file` otomatis ditolak dan diarahkan agar memakai `run_command`.
- *Catatan:* Untuk thread T3 Code yang sudah berjalan sebelum hook dipasang, buka thread baru agar `hooks.json` termuat.

### 2. Codex CLI & Pi dev CLI
```cmd
.venv\Scripts\python.exe connectors\install_connectors.py --apply codex
.venv\Scripts\python.exe connectors\install_connectors.py --apply pi
:: atau pasang semua sekaligus:
.venv\Scripts\python.exe connectors\install_connectors.py --apply all
```
Pastikan server `pii-shield` dalam status `RUNNING` sebelum memakai proxy Codex CLI (`chatgpt_base_url = "http://127.0.0.1:8787/chatgpt-backend/"`).

### Rollback
```cmd
.venv\Scripts\python.exe connectors\install_connectors.py --rollback
```
