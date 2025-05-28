import tkinter as tk
import pyperclip
import datetime
import time
from tkinter import ttk, messagebox, scrolledtext
from auth.auth_manager import AuthManager
from dotenv import load_dotenv

load_dotenv()

class DarkAuthSystemUI:
    def __init__(self):
        # Test security configs on startup
        from auth.auth_manager import AuthManager
        try:
            test_auth = AuthManager()
            print("✅ Security config validated successfully")
        except Exception as e:
            print(f"❌ Security error: {str(e)}")
            exit(1)

        self.auth = AuthManager()
        self.window = tk.Tk()
        self.window.title("SecureAuth Pro")
        self.window.geometry("450x400")
        self.window.resizable(False, False)
        
        # Configure dark theme colors
        self.bg_color = "#121212"  # Dark background
        self.card_color = "#1E1E1E"  # Slightly lighter cards
        self.fg_color = "#E0E0E0"  # Light text
        self.accent_color = "#BB86FC"  # Purple accent
        self.secondary_accent = "#03DAC6"  # Teal secondary
        self.error_color = "#CF6679"  # Error red
        self.success_color = "#4CAF50"  # Success green
        self.warning_color = "#FFA000"  # Warning amber
        
        self.setup_style()
        self.create_main_frame()

    def setup_style(self):
        style = ttk.Style()
        
        # Window background
        self.window.configure(bg=self.bg_color)
        
        # Create custom theme
        style.theme_create("dark_theme", parent="alt", settings={
            ".": {
                "configure": {
                    "background": self.bg_color,
                    "foreground": self.fg_color,
                    "troughcolor": self.card_color,
                    "selectbackground": self.accent_color,
                    "selectforeground": self.fg_color,
                    "fieldbackground": self.card_color,
                    "font": ("Segoe UI", 10)
                }
            },
            "TFrame": {
                "configure": {"background": self.bg_color}
            },
            "TLabel": {
                "configure": {
                    "background": self.bg_color,
                    "foreground": self.fg_color,
                    "font": ("Segoe UI", 11)
                }
            },
            "TButton": {
                "configure": {
                    "background": "#333333",
                    "foreground": self.fg_color,
                    "font": ("Segoe UI", 10, "bold"),
                    "padding": 8,
                    "relief": "flat",
                    "borderwidth": 0
                },
                "map": {
                    "background": [("active", "#424242")],
                    "foreground": [("disabled", "#757575")]
                }
            },
            "TEntry": {
                "configure": {
                    "fieldbackground": self.card_color,
                    "foreground": self.fg_color,
                    "insertcolor": self.fg_color,
                    "padding": 5,
                    "relief": "flat"
                }
            },
            "TCheckbutton": {
                "configure": {
                    "background": self.bg_color,
                    "foreground": self.fg_color,
                    "indicatormargin": 5
                }
            },
            "Vertical.TScrollbar": {
                "configure": {
                    "arrowsize": 14,
                    "troughcolor": self.bg_color,
                    "background": "#333333"
                },
                "map": {
                    "background": [("active", "#424242")]
                }
            }
        })
        style.theme_use("dark_theme")
        
        # Custom widget styles
        style.configure("Accent.TButton", 
                      background=self.accent_color,
                      foreground="#000000")
        style.map("Accent.TButton",
                background=[("active", "#9C64FF")])
        
        style.configure("Success.TButton",
                      background=self.success_color,
                      foreground="#000000")
        style.map("Success.TButton",
                background=[("active", "#3D8B40")])
        
        style.configure("Warning.TButton",
                      background=self.warning_color,
                      foreground="#000000")
        style.map("Warning.TButton",
                background=[("active", "#E69100")])
        
        style.configure("Error.TButton",
                      background=self.error_color,
                      foreground="#000000")
        style.map("Error.TButton",
                background=[("active", "#BA5D6E")])
        
        style.configure("Strength.TLabel",
                  font=("Segoe UI", 8),
                  anchor="w")
        
        style.configure("Toggle.TCheckbutton",
                    foreground=self.accent_color,
                    font=("Segoe UI", 10))
        style.map("TEntry",
                fieldbackground=[("focus", "#2A2A2A")],
                highlightcolor=[("focus", self.accent_color)],
                highlightthickness=[("focus", 1)])
        
        style.configure("TButton",
                    anchor="center") 
        
        style.configure("Accent.TButton",
                    anchor="center")
        
        style.configure("Success.TButton",
                    anchor="center")
        
        style.configure("Warning.TButton",
                    anchor="center")
        
        style.configure("Error.TButton",
                    anchor="center")
        
        style.configure("Back.TButton",
                    anchor="center")
        
        style.configure("Secondary.TButton",
                    anchor="center")
        
        style.configure("TButton",
              anchor="center",
              padding=(0, 5))
        
        style.configure("Back.TButton",
                    background=self.warning_color,
                    foreground="#000000",
                    anchor="center")

        style.map("Back.TButton",
                background=[("active", "#E69100")])

    def create_main_frame(self):
        self.clear_window()
        
        # Header with logo
        header_frame = ttk.Frame(self.window)
        header_frame.pack(pady=(30, 20), fill="x")
        
        ttk.Label(header_frame, 
                 text="🔒 SecureAuth Pro", 
                 font=("Segoe UI", 24, "bold"),
                 foreground=self.accent_color).pack()
        
        ttk.Label(self.window, 
                 text="Secure Authentication System", 
                 font=("Segoe UI", 12),
                 foreground="#B0B0B0").pack(pady=(0, 30))
        
        # Main buttons with icons
        buttons = [
            ("📝Register  ", self.show_register),
            ("🔑Login  ", self.show_login),
            ("🚪Exit  ", self.exit_application, "Warning.TButton")
        ]

        button_frame = ttk.Frame(self.window)
        button_frame.pack(pady=10)
        
        for i, (text, command, *style) in enumerate(buttons):
            btn = ttk.Button(button_frame, 
                        text=text, 
                        command=command,
                        style=style[0] if style else ("Accent.TButton" if "Login" in text else ""))
            btn.grid(row=i, column=0, pady=7, ipadx=30, sticky="ew")
            
        # Footer
        footer_frame = ttk.Frame(self.window)
        footer_frame.pack(side="bottom", fill="x", pady=10)
        
        ttk.Label(footer_frame, 
                 text="© 2024 SecureAuth Pro | v1.0.0", 
                 font=("Segoe UI", 8),
                 foreground="#616161").pack()

    def exit_application(self):
        self.window.quit()

    def show_register(self):
        self.clear_window()
        
        # Main container frame for centering
        container = ttk.Frame(self.window)
        container.pack(expand=True, fill="both", padx=15, pady=10)
        
        # Header with icon
        header_frame = ttk.Frame(container)
        header_frame.pack(pady=(30, 10))
        
        ttk.Label(header_frame,
                text="📝 User Registration", 
                font=("Segoe UI", 16, "bold"),
                foreground=self.accent_color).pack()
        
        # Form card
        form_card = ttk.Frame(container, style="Card.TFrame")
        form_card.pack(pady=5, ipadx=10, ipady=5, fill="x")
        
        # Form elements
        form_elements = ttk.Frame(form_card)
        form_elements.pack(pady=5, padx=10, fill="x")
        
        # Username field
        user_frame = ttk.Frame(form_elements)
        user_frame.pack(pady=5, fill="x")
        ttk.Label(user_frame, 
                text="👤 Username", 
                font=("Segoe UI", 9),
                foreground="#AAAAAA").pack(anchor="w")
        self.reg_user = ttk.Entry(user_frame, font=("Segoe UI", 10))
        self.reg_user.pack(fill="x", pady=(2, 0), ipady=4)
        
        # Password field with strength indicator
        pass_frame = ttk.Frame(form_elements)
        pass_frame.pack(pady=5, fill="x")
        ttk.Label(pass_frame, 
                text="🔒 Password", 
                font=("Segoe UI", 9),
                foreground="#AAAAAA").pack(anchor="w")
        self.reg_pass = ttk.Entry(pass_frame, show="•", font=("Segoe UI", 10))
        self.reg_pass.pack(fill="x", pady=(2, 0), ipady=4)
        self.reg_pass.bind("<KeyRelease>", self.update_password_strength)
        
        # Strength indicator with label
        strength_container = ttk.Frame(form_elements)
        strength_container.pack(fill="x", pady=(0, 5))
        
        ttk.Label(strength_container,
                text="Strength:",
                font=("Segoe UI", 8),
                foreground="#AAAAAA").pack(side="left")
        
        self.strength_frame = ttk.Frame(strength_container)
        self.strength_frame.pack(side="left", padx=0)
        
        self.strength_bars = []
        for i in range(4):
            # In show_register() method:
            bar = tk.Label(self.strength_frame, 
                        bg="#121212",
                        relief="flat",
                        bd=0,
                        width=12, 
                        height=1)
            bar.pack(side="left", padx=1)
            self.strength_bars.append(bar)
        
        # Checkboxes container
        check_frame = ttk.Frame(form_elements)
        check_frame.pack(pady=(5, 0), fill="x")
        
        self.reg_is_staff = tk.BooleanVar()
        ttk.Checkbutton(check_frame,
                    text="Staff Account",
                    variable=self.reg_is_staff,
                    style="Toggle.TCheckbutton").pack(anchor="w")
        
        # Button container
        button_frame = ttk.Frame(container)
        button_frame.pack(pady=(15, 0))
        
        ttk.Button(button_frame,
                text="⬅ Back",
                command=self.create_main_frame,
                style="Warning.TButton",
                width=10).pack(side="left", padx=5)
        
        ttk.Button(button_frame,
                text="📝 Register",
                command=self.do_register,
                style="Accent.TButton",
                width=15).pack(side="left", padx=5)
        
        # Footer
        footer_frame = ttk.Frame(container)
        footer_frame.pack(side="bottom", fill="x", pady=(10, 0))
        
        ttk.Label(footer_frame,
                text="By registering, you agree to our Terms and Privacy Policy",
                font=("Segoe UI", 8),
                foreground="#666666").pack()

    def check_password_strength(self, password):
        """Evaluate password strength and return score (0-4)"""
        score = 0
        
        # Length check
        if len(password) >= 8:
            score += 1
        
        # Digit check
        if any(char.isdigit() for char in password):
            score += 1
        
        # Uppercase check
        if any(char.isupper() for char in password):
            score += 1
        
        # Special char check
        special_chars = "!@#$%^&*()-+?_=,<>/"
        if any(char in special_chars for char in password):
            score += 1
        
        # Dictionary word check
        common_words = ["password", "123456", "qwerty", "letmein"]
        if password.lower() in common_words:
            score = max(0, score - 2)
        
        return min(4, score)

    def update_password_strength(self, event=None):
        password = self.reg_pass.get()
        score = self.check_password_strength(password)
        
        # Color scheme for strength meter
        colors = {
            0: "#e74c3c",  # Red
            1: "#e67e22",  # Orange
            2: "#f1c40f",  # Yellow
            3: "#2ecc71",  # Light green
            4: "#27ae60"   # Dark green
        }

        for i in range(4):
            if i < score:
                self.strength_bars[i].configure(background=colors[score])
            else:
                self.strength_bars[i].configure(background="#121212")

    def do_register(self):
        username = self.reg_user.get()
        password = self.reg_pass.get()
        is_staff = self.reg_is_staff.get()

        if not username or not password:
            messagebox.showerror("Error", "Username and password required", parent=self.window)
            return
        
        # Check password strength
        score = self.check_password_strength(password)
        if score < 2:
            messagebox.showwarning("Weak Password", 
                                "Password is too weak\n\n" +
                                "Tip: Use a mix of letters, numbers, and special characters",
                                parent=self.window)
            return
        
        if self.auth.register(username, password, is_staff):
            messagebox.showinfo("Success", "Registration successful! Please log in.", parent=self.window)
            self.show_login()
        else:
            messagebox.showerror("Error", "Username already exists", parent=self.window)

    def show_login(self):
        self.clear_window()
        
        # Header
        header_frame = ttk.Frame(self.window)
        header_frame.pack(pady=(80, 15), fill="x")
        
        ttk.Label(header_frame, 
                text="🔑 Login Options", 
                font=("Segoe UI", 16, "bold"),
                foreground=self.accent_color).pack()
        
        # Card frame for options
        card_frame = ttk.Frame(self.window, style="Card.TFrame")
        card_frame.pack(pady=10, padx=20, fill="x", ipady=5) 
        
        # Buttons with combined title and description
        options = [
            ("👤 Login with your username and password", self.show_normal_login),
            ("🔐 Login with an authentication token", self.show_token_login)
        ]
        
        for i, (text, command) in enumerate(options):
            btn = ttk.Button(card_frame, 
                    text=text, 
                    command=command,
                    style="Accent.TButton" if i == 0 else "Secondary.TButton",
                    compound='left',
                    padding=(10, 8), 
                    width=35)
            btn.pack(pady=8, padx=10, fill='x')
        
        # Back button
        button_frame = ttk.Frame(self.window)
        button_frame.pack(pady=8)
        
        ttk.Button(button_frame,
                text="⬅ Back",
                command=self.create_main_frame,
                style="Warning.TButton",
                width=10).pack()
        
        # Footer frame
        footer_frame = ttk.Frame(self.window)
        footer_frame.pack(side="bottom", fill="x", pady=10)
        
        ttk.Label(footer_frame, 
                text="© 2024 SecureAuth Pro | v1.0.0", 
                font=("Segoe UI", 8),
                foreground="#616161").pack()

    def show_normal_login(self):
        self.clear_window()
        
        # Main container frame for centering
        container = ttk.Frame(self.window)
        container.pack(expand=True, fill="both", padx=15, pady=10)
        
        # Header with icon
        header_frame = ttk.Frame(container)
        header_frame.pack(pady=(40, 10))
        
        ttk.Label(header_frame,
                text="🔑 User Login", 
                font=("Segoe UI", 16, "bold"),
                foreground=self.accent_color).pack()
        
        # Form card
        form_card = ttk.Frame(container, style="Card.TFrame")
        form_card.pack(pady=5, ipadx=10, ipady=5, fill="x")
        
        # Form elements
        form_elements = ttk.Frame(form_card)
        form_elements.pack(pady=5, padx=10, fill="x")
        
        # Username field
        user_frame = ttk.Frame(form_elements)
        user_frame.pack(pady=5, fill="x")
        ttk.Label(user_frame, 
                text="👤 Username", 
                font=("Segoe UI", 9),
                foreground="#AAAAAA").pack(anchor="w")
        self.login_user = ttk.Entry(user_frame, font=("Segoe UI", 10))
        self.login_user.pack(fill="x", pady=(2, 0), ipady=4)
        
        # Password field
        pass_frame = ttk.Frame(form_elements)
        pass_frame.pack(pady=5, fill="x")
        ttk.Label(pass_frame, 
                text="🔒 Password", 
                font=("Segoe UI", 9),
                foreground="#AAAAAA").pack(anchor="w")
        self.login_pass = ttk.Entry(pass_frame, show="•", font=("Segoe UI", 10))
        self.login_pass.pack(fill="x", pady=(2, 0), ipady=4)
        
        # Staff checkbox
        check_frame = ttk.Frame(form_elements)
        check_frame.pack(pady=(5, 0), fill="x")
        
        self.login_is_staff = tk.BooleanVar()
        ttk.Checkbutton(check_frame,
                    text="I am a staff member",
                    variable=self.login_is_staff,
                    style="Toggle.TCheckbutton").pack(anchor="w")
        
        # Button container
        button_frame = ttk.Frame(container)
        button_frame.pack(pady=(15, 0))
        
        ttk.Button(button_frame,
                text="⬅ Back",
                command=self.show_login,
                style="Warning.TButton",
                width=10).pack(side="left", padx=5)
        
        ttk.Button(button_frame,
                text="Login 🔑",
                command=self.do_login,
                style="Accent.TButton",
                width=15).pack(side="left", padx=5)
        
        # Footer
        footer_frame = ttk.Frame(container)
        footer_frame.pack(side="bottom", fill="x", pady=(10, 0))
        
        ttk.Label(footer_frame,
                text="© 2024 SecureAuth Pro | v1.0.0",
                font=("Segoe UI", 8),
                foreground="#666666").pack()

    def do_login(self):
        username = self.login_user.get()
        password = self.login_pass.get()
        is_staff = self.login_is_staff.get()

        user_data = self.auth.get_user_data(username)
        
        if user_data:
            is_registered_staff = user_data.get("is_staff", False)
            
            if is_registered_staff and not is_staff:
                messagebox.showerror("Error", "Invalid credentials", parent=self.window)
                return
            
            if token := self.auth.login(username, password, is_staff):
                self.show_home_screen(token)
            else:
                messagebox.showerror("Error", "Invalid credentials", parent=self.window)
        else:
            messagebox.showerror("Error", "User not found", parent=self.window)

    def show_token_login(self):
        self.clear_window()
        
        # Main container frame for centering
        container = ttk.Frame(self.window)
        container.pack(expand=True, fill="both", padx=15, pady=10)
        
        # Header with icon
        header_frame = ttk.Frame(container)
        header_frame.pack(pady=(60, 10))
        
        ttk.Label(header_frame,
                text="🔐 Token Login", 
                font=("Segoe UI", 16, "bold"),
                foreground=self.accent_color).pack()
        
        # Form card
        form_card = ttk.Frame(container, style="Card.TFrame")
        form_card.pack(pady=5, ipadx=10, ipady=5, fill="x")
        
        # Form elements
        form_elements = ttk.Frame(form_card)
        form_elements.pack(pady=5, padx=10, fill="x")
        
        # Token field
        token_frame = ttk.Frame(form_elements)
        token_frame.pack(pady=5, fill="x")
        ttk.Label(token_frame, 
                text="🔑 Authentication Token", 
                font=("Segoe UI", 9),
                foreground="#AAAAAA").pack(anchor="w")
        
        self.token_entry = scrolledtext.ScrolledText(token_frame,
                                                width=40,
                                                height=4,
                                                wrap=tk.WORD,
                                                bg=self.card_color,
                                                fg=self.fg_color,
                                                insertbackground=self.fg_color,
                                                font=("Consolas", 9),
                                                relief="flat",
                                                highlightbackground="#333333",
                                                highlightcolor=self.accent_color,
                                                highlightthickness=1)
        self.token_entry.pack(fill="x", pady=(2, 0))
        
        # Button container
        button_frame = ttk.Frame(container)
        button_frame.pack(pady=(15, 0))
        
        ttk.Button(button_frame,
                text="⬅ Back",
                command=self.show_login,
                style="Warning.TButton",
                width=10).pack(side="left", padx=5)
        
        ttk.Button(button_frame,
                text="Paste 📋",
                command=self.paste_token,
                style="Secondary.TButton",
                width=12).pack(side="left", padx=5)
        
        ttk.Button(button_frame,
                text="Login 🔐",
                command=self.do_token_login,
                style="Accent.TButton",
                width=12).pack(side="left", padx=5)
        
        # Footer
        footer_frame = ttk.Frame(container)
        footer_frame.pack(side="bottom", fill="x", pady=(10, 0))
        
        ttk.Label(footer_frame,
                text="© 2024 SecureAuth Pro | v1.0.0",
                font=("Segoe UI", 8),
                foreground="#666666").pack()

    def paste_token(self):
        try:
            token = self.window.clipboard_get()
            self.token_entry.delete("1.0", tk.END)
            self.token_entry.insert(tk.INSERT, token)
        except tk.TclError:
            messagebox.showerror("Error", "No token found in clipboard", parent=self.window)

    def do_token_login(self):
        token = self.token_entry.get("1.0", tk.END).strip()
        if not token or not (payload := self.auth.validate_token(token)):
            messagebox.showerror("Error", "Invalid or expired token", parent=self.window)
        else:
            self.show_home_screen(token)

    def show_home_screen(self, token):
        if not self.auth.validate_token(token):
            messagebox.showerror("Error", "Invalid token, please login again", parent=self.window)
            return self.show_login()
        self.clear_window()
        
        # Main container frame for centering
        container = ttk.Frame(self.window)
        container.pack(expand=True, fill="both", padx=15, pady=10)
        
        # Decode token to get user info
        payload = self.auth.decode_token(token)
        
        if payload:
            username = payload.get("user", "Unknown User")
            exp = payload.get("exp", None)
            
            # Header with welcome message
            header_frame = ttk.Frame(container)
            header_frame.pack(pady=(40, 10))
            
            ttk.Label(header_frame,
                    text=f"Welcome, {username}!", 
                    font=("Segoe UI", 16, "bold"),
                    foreground=self.accent_color).pack()
            
            # Token info card
            info_card = ttk.Frame(container, style="Card.TFrame")
            info_card.pack(pady=5, ipadx=10, ipady=5, fill="x")
            
            # Token status frame
            status_frame = ttk.Frame(info_card)
            status_frame.pack(pady=(10, 5), padx=10, fill="x")
            
            ttk.Label(status_frame,
                    text="Token Status:",
                    font=("Segoe UI", 9),
                    foreground="#AAAAAA").pack(side="left")
            
            self.countdown_label = ttk.Label(status_frame,
                                        text="Valid" if not exp else "Counting down...",
                                        font=("Segoe UI", 9, "bold"),
                                        foreground=self.success_color)
            self.countdown_label.pack(side="left", padx=5)
            
            # Token display
            ttk.Label(info_card,
                    text="Your Authentication Token:",
                    font=("Segoe UI", 9),
                    foreground="#AAAAAA").pack(pady=(5, 0), padx=10, anchor="w")
            
            token_display = scrolledtext.ScrolledText(info_card,
                                                width=45,
                                                height=4,
                                                wrap=tk.WORD,
                                                bg=self.card_color,
                                                fg=self.fg_color,
                                                font=("Consolas", 8),
                                                relief="flat",
                                                highlightbackground="#333333",
                                                highlightcolor=self.accent_color,
                                                highlightthickness=1)
            token_display.pack(pady=(0, 10), padx=10, fill="x")
            token_display.insert(tk.INSERT, token)
            token_display.configure(state='disabled')
            
            # Button container
            button_frame = ttk.Frame(container)
            button_frame.pack(pady=(15, 0))
            
            ttk.Button(button_frame,
                    text="Copy Token 📋",
                    command=lambda: self.copy_token(token),
                    style="Secondary.TButton",
                    width=15).pack(side="left", padx=5)
            
            ttk.Button(button_frame,
                text="Refresh Token 🔄",
                command=lambda t=token: self.refresh_token(t), 
                style="Secondary.TButton").pack(side="left", padx=5)
            
            ttk.Button(button_frame,
                    text="Logout 🚪",
                    command=self.create_main_frame,
                    style="Warning.TButton",
                    width=10).pack(side="left", padx=5)
            
            # Footer
            footer_frame = ttk.Frame(container)
            footer_frame.pack(side="bottom", fill="x", pady=(10, 0))
            
            ttk.Label(footer_frame,
                    text="© 2024 SecureAuth Pro | v1.0.0",
                    font=("Segoe UI", 8),
                    foreground="#666666").pack()
            
            # Start countdown if token has expiration
            if exp:
                if hasattr(self, 'countdown_job'):
                    self.window.after_cancel(self.countdown_job)
                self.update_countdown(exp)

    def refresh_token(self, old_token):
        """Enhanced UI refresh handler with detailed error messages"""
        try:
            if not old_token:
                messagebox.showerror("Error", "No token provided", parent=self.window)
                return
                
            new_token = self.auth.refresh_token(old_token)
            if new_token:
                self.show_home_screen(new_token)
                messagebox.showinfo("Success", "Token refreshed successfully!", parent=self.window)
            else:
                messagebox.showerror("Error", 
                    "Refresh failed:\n1. Token may be invalid\n2. Your account may have been removed\n3. System time may be out of sync",
                    parent=self.window)
        except Exception as e:
            messagebox.showerror("Error", f"Critical error during refresh:\n{str(e)}", parent=self.window)

    def copy_token(self, token):
        pyperclip.copy(token)
        messagebox.showinfo("Token Copied", "Your authentication token has been copied to clipboard!", parent=self.window)

    def update_countdown(self, exp):
        remaining_time = int(exp - time.time())
        if remaining_time > 0:
            minutes, seconds = divmod(remaining_time, 60)
            hours, minutes = divmod(minutes, 60)
            
            if self.countdown_label.winfo_exists():
                if remaining_time < 300:
                    color = self.error_color
                elif remaining_time < 900:
                    color = self.warning_color
                else:
                    color = self.success_color
                
                self.countdown_label.config(
                    text=f"{hours:02}:{minutes:02}:{seconds:02} remaining",
                    foreground=color
                )
                self.countdown_job = self.window.after(1000, lambda: self.update_countdown(exp))
        else:
            if self.countdown_label.winfo_exists():
                self.countdown_label.config(text="Token Expired!", foreground=self.error_color)
                messagebox.showwarning("Token Expired", "Your authentication token has expired.", parent=self.window)

    def clear_window(self):
        for widget in self.window.winfo_children():
            widget.destroy()

    def run(self):
        self.window.mainloop()

if __name__ == "__main__":
    app = DarkAuthSystemUI()
    app.run()