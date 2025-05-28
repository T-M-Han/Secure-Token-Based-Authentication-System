import bcrypt
import jwt
import json
import os
from datetime import datetime, timedelta
from dotenv import load_dotenv

load_dotenv(override=True)

class AuthManager:
    USERS_FILE = "users.json"
    SECRET_KEY = os.getenv("SECRET_KEY")
    TOKEN_ALGORITHM = os.getenv("TOKEN_ALGORITHM", "HS256")
    TOKEN_EXPIRY_SECONDS = int(os.getenv("TOKEN_EXPIRY_SECONDS", "30")) 

    def __init__(self):
        self._validate_secrets()
        self.users = self.load_users()

    def _validate_secrets(self):
        # Ensure critical environment variables are valid
        if not self.SECRET_KEY:
            raise ValueError("SECRET_KEY not found in .env file")
        if len(self.SECRET_KEY) < 32:
            raise ValueError("SECRET_KEY must be ≥32 characters")
        if self.TOKEN_ALGORITHM not in ["HS256", "HS384", "HS512"]:
            raise ValueError("Unsupported token algorithm")

    def load_users(self):
        # Load users from local JSON file
        if os.path.exists(self.USERS_FILE):
            with open(self.USERS_FILE, "r") as file:
                return json.load(file)
        return {}

    def save_users(self):
        # Save users to local JSON file
        with open(self.USERS_FILE, "w") as file:
            json.dump(self.users, file, indent=4)

    def register(self, username, password, is_staff=False, permissions=None):
        if username in self.users:
            return False
        
        if permissions is None:
            permissions = ["read"]
            if is_staff:
                permissions.append("write")
        
        hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        self.users[username] = {
            "password": hashed_pw,
            "is_staff": is_staff,
            "permissions": permissions
        }
        self.save_users()
        return True

    def login(self, username, password, is_staff=False):
        # Authenticate user and return JWT token
        if username not in self.users:
            return None

        stored_data = self.users[username]
        stored_hash = stored_data["password"].encode()

        if bcrypt.checkpw(password.encode(), stored_hash):
            if is_staff and not stored_data["is_staff"]:
                return None 
            
            expiration_time = datetime.utcnow() + timedelta(seconds=self.TOKEN_EXPIRY_SECONDS)
            token_payload = {
                "user": username,
                "permissions": stored_data["permissions"],
                "system": "auth_system",
                "iat": datetime.utcnow(),
                "exp": expiration_time
            }
            token = jwt.encode(token_payload, self.SECRET_KEY, algorithm=self.TOKEN_ALGORITHM)
            return token

        return None

    def get_user_data(self, username):
        # Retrieve user details
        return self.users.get(username)

    def validate_token(self, token):
        # Verify JWT token validity
        try:
            payload = jwt.decode(token, self.SECRET_KEY, algorithms=["HS256"])
            return payload
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None

    def decode_token(self, token):
        # Decode token without verifying expiration
        try:
            payload = jwt.decode(token, self.SECRET_KEY, algorithms=["HS256"], options={"verify_exp": False})
            return payload
        except jwt.InvalidTokenError:
            return None

    def refresh_token(self, old_token):
        # Refresh token using existing payload
        try:
            payload = jwt.decode(
                old_token,
                self.SECRET_KEY,
                algorithms=[self.TOKEN_ALGORITHM],
                options={"verify_exp": False}
            )
            user_data = self.users.get(payload.get("user"))
            if not user_data:
                return None
                
            new_payload = {
                "user": payload["user"],
                "permissions": user_data["permissions"],
                "system": "auth_system",
                "iat": datetime.utcnow(),
                "exp": datetime.utcnow() + timedelta(seconds=self.TOKEN_EXPIRY_SECONDS)
            }
            return jwt.encode(new_payload, self.SECRET_KEY, algorithm=self.TOKEN_ALGORITHM)
            
        except jwt.InvalidSignatureError:
            pass
        except jwt.DecodeError:
            pass
        except Exception:
            pass
        return None
    