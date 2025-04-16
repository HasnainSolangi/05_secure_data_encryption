# 🛡️ Secure Data Encryption System using Streamlit - Project 05 (Python)

This is a **Secure Data Vault** built using Python and Streamlit that allows users to safely encrypt, store, and retrieve their private information with a unique passkey. With in-memory storage and advanced encryption, this system ensures your data stays secure and accessible only to you.

---

## 🎯 Objective

- ✅ Allow users to **encrypt and store data** with a custom passkey.
- ✅ Enable **decryption** only with the correct passkey.
- ✅ Enforce a **3-attempt failure lockout** before login re-authorization is required.
- ✅ Provide a clean, interactive **Streamlit-based interface** for secure interactions.

---

## 🔐 Core Features

- 🔒 **Fernet Encryption** (AES-based symmetric encryption)
- 🔐 **SHA-256 hashing** for passkeys
- 🚫 **No external database** (everything stored in-memory using Python dictionaries)
- 🚷 **3 Failed Attempts Protection** with forced login redirect
- 🔑 Simple **Admin Login** for reauthorization
- 🌐 **Fully built with Streamlit** – interactive, real-time UI

---

## 🧩 How It Works

### 🔄 In-Memory Structure

Each entry is stored in-memory like this:

```python
stored_data = {
  "some_encrypted_text": {
    "encrypted_text": "xyz",
    "passkey": "hashed_passkey",
    "label": "Optional user label"
  },
  ...
}
```

---

## 📁 Pages / Modules

| Page              | Description                                                                 |
|-------------------|-----------------------------------------------------------------------------|
| 🏠 **Home**        | App overview and quick guide                                                |
| 📂 **Store Data**  | Input plaintext and a passkey to store securely                            |
| 🔍 **Retrieve Data**| Retrieve encrypted data by providing the matching passkey                  |
| 🔑 **Login Page**   | Triggered after 3 failed attempts; resets session upon correct admin login |

---

## 🔐 Security Mechanism

- Users must provide **correct passkey** for decryption.
- Passkey is hashed and matched internally.
- After **3 incorrect attempts**, system **locks retrieval** and redirects to login.
- Only after successful admin re-login is access restored.

---

## 🧪 Sample Flow

1. Go to `Store Data` → Input any text and a passkey → Data gets encrypted and stored.
2. Go to `Retrieve Data` → Input encrypted string + passkey.
3. ✅ Correct? → You get your original data.
4. ❌ Wrong? → Failed attempt counter increases.
5. After 3 wrong tries → 🔒 You’re redirected to the Login Page.
6. Login using master password → ✅ Access restored.

---

## 🚀 How to Run

### 1. Clone the Repository

```bash
git clone https://github.com/HasnainSolangi/05_secure_data_encryption.git
cd 05_secure_data_encryption
```

### 2. Install Required Packages

```bash
pip install streamlit cryptography
```

### 3. Run the Streamlit App

```bash
streamlit run secure_data_encryption.py
```

---

## 🔑 Default Login Credentials

| Role   | Password   |
|--------|------------|
| Admin  | `admin123` |

> Note: You can change the default admin password directly in the login page code block for better security.

---

## 🧠 Concepts Practiced

- 🔁 Control Flow (Conditions, Loops)
- 📦 Data Structures (Dictionaries, Strings)
- 🔐 Encryption & Decryption (Fernet AES)
- 🧂 SHA-256 Hashing
- 🧠 Streamlit Components & Session State
- 🔁 Page Routing and Redirection in Streamlit
- ⚠️ Login & Re-authentication Logic

---

## 📌 Bonus Goals / Future Scope

- [ ] ✅ Store encrypted data in a **JSON file** for persistence
- [ ] 🔐 Implement **PBKDF2** or **bcrypt** for enhanced hashing
- [ ] 👥 Enable **Multi-User Accounts**
- [ ] ⏱️ Add **Time-based Lockout** after failed attempts
- [ ] 🎨 Add themes (Light/Dark Mode Toggle)

---

## 🖼️ Screenshots

![screenshot](https://via.placeholder.com/900x500?text=Secure+Data+Encryption+System+%7C+Streamlit+UI)

---

## 📜 License

This project is developed as part of the **GIAIC Python Assignment Series**.  
For learning and educational purposes only.

---

## 👨‍🎓 Developed By

**Hasnain Ahmed**  
📧 hasnainzahoor1996@gmail.com  
🌐 [LinkedIn](https://www.linkedin.com/in/hasnainahmed90s/)

---

> “Secure today, safe tomorrow.” 🔐
```