import jwt
import bcrypt
import os
from datetime import datetime, timedelta
from dotenv import load_dotenv

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
TOKEN_ALGORITHM = os.getenv("TOKEN_ALGORITHM", "HS256")

# Basic validation for critical secret settings
if not SECRET_KEY:
    raise ValueError("SECRET_KEY must be set in .env")
if len(SECRET_KEY) < 32:
    raise ValueError("SECRET_KEY must be ≥32 characters")

def hash_password(password):
    # Generate hashed password using bcrypt
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(password, hashed_password):
    # Check password against hashed value
    return bcrypt.checkpw(password.encode(), hashed_password.encode())

def create_token(username, permissions, role, valid_hours=1):
    # Create JWT token with user info and expiry
    payload = {
        "user": username,
        "permissions": permissions,
        "role": role,
        "system": "auth_system",
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(hours=valid_hours)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=TOKEN_ALGORITHM)

def validate_token(token):
    # Validate JWT and return payload if valid
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[TOKEN_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None
