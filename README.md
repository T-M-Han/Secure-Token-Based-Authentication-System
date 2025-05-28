# Secure-Token-Based-Authentication-System
Developed a secure JWT-based authentication system in Python with Tkinter GUI, implementing industry-standard security practices.

## Features
1. Token Security:
- JWT with HMAC-SHA256 signing.
- Short-lived access tokens (30s) + refresh mechanism.
- Anti-tampering via signature validation.

2. Password Handling:
- Bcrypt hashing with salting.

3. Architecture:
- Modular design (auth logic, crypto, GUI separation).
- Secrets stored in environment variables (production: HSMs/vaults).

4. UI Protections:
- Clipboard auto-clear (45s), password strength meter.

## Technology Stack
- **Python**
- **PyJWT**
- **bcrypt**
- **Tkinter**

## Installation
1. Clone the repository: git clone - https://github.com/T-M-Han/Secure-Token-Based-Authentication-System.git
2. Move files:Copy the main filer to your VSCode.
3. Open Terminal and Run python ui.py

## Usage
1. Register or log in as a user or staff.
2. Browse Home Screen
3. Check Token and Validate Login again

## Folder Structure
- auth_system_ui   - Contains project files
- README.md     

## Contact
Thaw Myo Han  
- Email: thawmyohan736@gmail.com
- LinkedIn: (https://linkedin.com/in/han2873292a7/)
- GitHub: (https://github.com/T-M-Han)
