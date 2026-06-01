# CodeAlpha — Task 2: Detecting Data Leaks Using SQL Injection

> **CodeAlpha Cloud Computing Internship**

A full-stack Python/Flask web application with **double-layer SQL injection defense**, **AES-256 credential encryption**, and **capability token access control** — accessible over the internet with zero heavy infrastructure.

---

## 🛡 Security Architecture — Double Layer

```
User Input
    │
    ▼
┌──────────────────────────────────────┐
│  LAYER 1 — sql_defense.py            │
│  • 15 regex attack signatures        │
│  • Keyword density analysis          │
│  • Quote imbalance detection         │
│  • URL-encoded bypass detection      │
│  → BLOCKS attack before hitting DB   │
└──────────────┬───────────────────────┘
               │ clean input only
               ▼
┌──────────────────────────────────────┐
│  LAYER 2 — database.py               │
│  • 100% parameterised queries        │
│  • Zero string-interpolated SQL      │
│  → PREVENTS injection at DB level    │
└──────────────┬───────────────────────┘
               │
               ▼
┌──────────────────────────────────────┐
│  STORAGE — secure.sqlite             │
│  • Passwords: PBKDF2-HMAC-SHA256     │
│  • Email/Phone: AES-256-CBC          │
│  • All events: audit_log table       │
└──────────────────────────────────────┘
```

---

## 📁 Project Structure

```
CodeAlpha_SQLInjectionDefense/
│
├── src/
│   ├── app.py              # Flask web server (routes)
│   ├── sql_defense.py      # Layer 1 — SQLi detection engine
│   ├── database.py         # Layer 2 — Secure parameterised DB
│   └── encryption.py       # AES-256-CBC + PBKDF2 password hash
│
├── templates/
│   ├── index.html          # Login / Register page
│   ├── dashboard.html      # User profile after login
│   ├── attack_demo.html    # Live SQL injection demo
│   └── logs.html           # Attack log viewer
│
├── tests/
│   └── test_system.py      # 20 pytest unit tests
│
├── data/                   # SQLite DB (created at runtime)
├── requirements.txt
└── README.md
```

---

## 🚀 How to Run (VS Code)

### 1. Clone and open
```bash
git clone https://github.com/<your-username>/CodeAlpha_SQLInjectionDefense.git
cd CodeAlpha_SQLInjectionDefense
```

### 2. Create virtual environment
```bash
python -m venv venv

# Windows
venv\Scripts\activate

# macOS / Linux
source venv/bin/activate
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Run the server
```bash
cd src
python app.py
```

Open your browser: **http://127.0.0.1:5000**

### 5. Run tests
```bash
cd ..
python -m pytest tests/ -v
```

---

## 🌐 Pages to Show in Your Demo Video

| URL | What to show |
|---|---|
| `http://localhost:5000` | Login + Register page |
| `http://localhost:5000/attack-demo` | **Click attack presets** — see BLOCKED / CRITICAL |
| `http://localhost:5000/logs` | All blocked attacks logged with level + payload |
| Register → Login → Dashboard | AES-256 decrypted email shown in profile |

---

## 🔥 Features

| Feature | Implementation |
|---|---|
| **SQLi Pattern Detection** | 15 compiled regex signatures covering all attack types |
| **Keyword Density Analysis** | Blocks inputs with abnormally high SQL keyword ratio |
| **URL-encoded bypass detection** | Decodes and re-scans `%27%20OR%20...` attacks |
| **AES-256-CBC Encryption** | Email and phone encrypted at rest; random IV per record |
| **PBKDF2 Password Hashing** | 200,000 rounds, salt per password, constant-time compare |
| **Capability Tokens** | 32-byte `secrets.token_urlsafe` tokens, 1-hour expiry |
| **Attack Logging** | Every blocked attempt logged with payload, level, IP, timestamp |
| **Audit Trail** | Login success/fail, registration events all logged |

---

## ⚔️ Attack Types Detected

- Classic tautologies: `' OR '1'='1`
- UNION-based data extraction: `UNION SELECT * FROM users`
- Destructive queries: `DROP TABLE`, `DELETE FROM`, `TRUNCATE`
- Comment truncation: `admin'--`, `admin'#`
- Blind time-based: `SLEEP(5)`, `WAITFOR DELAY`
- Schema probing: `information_schema.tables`
- Stored procedure abuse: `xp_cmdshell`, `sp_executesql`
- Hex encoding: `0x41 CHAR(65)`
- URL-encoded bypasses: `%27 OR %271%27%3D%271`

---

## 👨‍💻 Author

**[Your Name]**  
CodeAlpha Cloud Computing Intern  
[LinkedIn] | [GitHub]

---

## 📄 License

Submitted as part of the **CodeAlpha Internship Programme**.
