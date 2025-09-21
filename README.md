# Advanced Password Manager v2.0

A production-ready, secure password manager with zero-knowledge architecture, built with Python and Streamlit. Features military-grade encryption, password health monitoring, and advanced security features.

## 🌐 Live Demo
Site Link: https://password-manager-app-1-gvse.onrender.com

## ✨ New Features in v2.0

### 🔐 **Zero-Knowledge Architecture**
- Master password never stored on disk
- PBKDF2 key derivation with 100,000 iterations
- Automatic session timeout after 15 minutes of inactivity
- Secure authentication system

### 📊 **Password Health Dashboard**
- Real-time password strength analysis
- Duplicate password detection
- Password age monitoring (alerts for passwords >90 days)
- Visual analytics with interactive charts
- Security score and recommendations

### 🎲 **Advanced Password Generator**
- Customizable length (8-32 characters)
- Character type selection (uppercase, lowercase, numbers, symbols)
- Ambiguous character exclusion option
- Cryptographically secure random generation

### 📦 **Import/Export Functionality**
- Export to encrypted JSON or CSV formats
- Import from other password managers
- Backup and restore capabilities
- Data portability

### 🔍 **Enhanced Search**
- Search across websites, usernames, categories, and notes
- Filter by categories
- Sort by name, date, or category
- Quick access to frequently used passwords

### 🏷️ **Organization Features**
- Category-based organization
- Notes for additional information
- Creation and update timestamps
- Bulk operations support

## 🔒 Security Features

- **AES-256 Encryption**: Military-grade encryption for all passwords
- **Zero-Knowledge**: Master password never stored, only used for key derivation
- **PBKDF2 Key Derivation**: 100,000 iterations for brute-force resistance
- **Secure Random Generation**: Using Python's `secrets` module
- **Session Management**: Automatic timeout and manual lock
- **No Cloud Storage**: All data stored locally for maximum privacy
- **Password Strength Validation**: Real-time strength checking
- **Secure Export**: Encrypted exports with warnings for plain-text

## 📋 Requirements

- Python 3.8+
- Streamlit 1.33.0
- cryptography 42.0.5
- pandas 2.2.1
- plotly 5.20.0