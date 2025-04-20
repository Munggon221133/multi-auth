# app.py
import streamlit as st
import psycopg2
import pyotp
import qrcode
import io
import base64
import hashlib
import re
from datetime import datetime

# Configure page
st.set_page_config(page_title="Secure Login System", layout="centered")

# Initialize session state
if "page" not in st.session_state:
    st.session_state.page = "login"  # Default page is login
if "temp_user_data" not in st.session_state:
    st.session_state.temp_user_data = {}
if "auth_message" not in st.session_state:
    st.session_state.auth_message = None

# Utility to hash password with salt
def hash_password(password):
    salt = "securesalt"  # In a real app, use a unique salt per user
    return hashlib.sha256((password + salt).encode()).hexdigest()

# DB connection
def get_connection():
    return psycopg2.connect(
        host="db",
        database="database",
        user="postgres",
        password="password"
    )

# Ensure tables exist
def init_database():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        first_name TEXT NOT NULL,
        last_name TEXT NOT NULL,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        totp_secret TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)
    
    # Create table for login history
    cur.execute("""
    CREATE TABLE IF NOT EXISTS login_history (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        status TEXT NOT NULL
    );
    """)
    
    conn.commit()
    cur.close()
    conn.close()

# Generate username from first and last name
def generate_username(first_name, last_name):
    username = f"{first_name.lower()}.{last_name[:3].lower()}@company.com"
    
    # Check if username exists
    conn = get_connection()
    cur = conn.cursor()
    
    # Query to find similar usernames
    cur.execute("SELECT username FROM users WHERE username LIKE %s", 
                (f"{first_name.lower()}.{last_name[:3].lower()}%",))
    existing_usernames = [row[0] for row in cur.fetchall()]
    
    if username in existing_usernames:
        # If username exists, add a number
        counter = 1
        while f"{first_name.lower()}.{last_name[:3].lower()}{counter}@company.com" in existing_usernames:
            counter += 1
        username = f"{first_name.lower()}.{last_name[:3].lower()}{counter}@company.com"
    
    cur.close()
    conn.close()
    return username

# Validate password strength
def is_password_strong(password):
    # Minimum 8 characters, at least one uppercase letter, one lowercase letter, and one number
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one number"
    return True, "Password is strong"

# Generate QR code as base64 image
def generate_qr_code(uri):
    qr = qrcode.make(uri)
    buf = io.BytesIO()
    qr.save(buf)
    buf.seek(0)
    return base64.b64encode(buf.read()).decode("utf-8")

# Initialize the database
init_database()

# Custom CSS
st.markdown("""
<style>
    .main-container {
        max-width: 800px;
        margin: 0 auto;
        padding: 20px;
    }
    .auth-form {
        background-color: #f7f7f7;
        padding: 30px;
        border-radius: 10px;
        box-shadow: 0 2px 10px rgba(0,0,0,0.1);
    }
    .centered-text {
        text-align: center;
    }
</style>
""", unsafe_allow_html=True)

# Navigation functions
def go_to_signup():
    st.session_state.page = "signup"
    st.session_state.temp_user_data = {}
    st.session_state.auth_message = None

def go_to_login():
    st.session_state.page = "login"
    st.session_state.temp_user_data = {}
    st.session_state.auth_message = None

def go_to_qr_setup():
    st.session_state.page = "qr_setup"

def go_to_dashboard():
    st.session_state.page = "dashboard"

# Login Page
if st.session_state.page == "login":
    with st.container():
        st.subheader("Login")
        
        username = st.text_input("Username (email)", key="login_username")
        password = st.text_input("Password", type="password", key="login_password")
        totp_code = st.text_input("6-digit Authenticator Code", key="login_totp")
        
        button_container = st.container()
        
        with button_container:
            col1, col2 = st.columns([4, 1])
            
            with col1:
                login_button = st.button("Login")
            
            with col2:
                no_account_button = st.button("No account yet?")
                
                # This button will be styled as a link and aligned to the right
                if no_account_button:
                    go_to_signup()
                    st.experimental_rerun()
        
        if login_button:
            if not username or not password or not totp_code:
                st.error("All fields are required!")
            else:
                # Validate login
                conn = get_connection()
                cur = conn.cursor()
                cur.execute("SELECT id, password, totp_secret FROM users WHERE username = %s", (username,))
                result = cur.fetchone()
                
                if result:
                    user_id, stored_pw, secret = result
                    if hash_password(password) == stored_pw:
                        totp = pyotp.TOTP(secret)
                        if totp.verify(totp_code):
                            # Record successful login
                            cur.execute(
                                "INSERT INTO login_history (user_id, status) VALUES (%s, %s)",
                                (user_id, "success")
                            )
                            conn.commit()
                            
                            # Set session user data
                            st.session_state.user_id = user_id
                            st.session_state.username = username
                            
                            st.success("Login successful!")
                            go_to_dashboard()
                            st.experimental_rerun()
                        else:
                            st.error("Invalid authentication code.")
                            # Record failed login
                            cur.execute(
                                "INSERT INTO login_history (user_id, status) VALUES (%s, %s)",
                                (user_id, "failed_totp")
                            )
                            conn.commit()
                    else:
                        st.error("Invalid password.")
                        if result[0]:
                            # Record failed login
                            cur.execute(
                                "INSERT INTO login_history (user_id, status) VALUES (%s, %s)",
                                (user_id, "failed_password")
                            )
                            conn.commit()
                else:
                    st.error("Username not found.")
                
                cur.close()
                conn.close()

# Signup Page
elif st.session_state.page == "signup":
    with st.container():
        st.subheader("Create a new account")
        
        first_name = st.text_input("First Name", key="signup_first_name")
        last_name = st.text_input("Last Name", key="signup_last_name")
        password = st.text_input("Password", type="password", key="signup_password")
        confirm_password = st.text_input("Confirm Password", type="password", key="signup_confirm")
        
        col1, col2 = st.columns([1, 4])
        
        with col1:
            signup_button = st.button("Create Account")
        
        with col2:
            back_to_login_button = st.button("Back to Login")
            if back_to_login_button:
                go_to_login()
                st.experimental_rerun()
        
        if signup_button:
            if not first_name or not last_name:
                st.error("First name and last name are required!")
            elif password != confirm_password:
                st.error("Passwords do not match!")
            else:
                is_strong, message = is_password_strong(password)
                if not is_strong:
                    st.error(message)
                else:
                    # Generate username
                    username = generate_username(first_name, last_name)
                    
                    # Generate TOTP secret
                    totp_secret = pyotp.random_base32()
                    
                    # Store user data in session state
                    st.session_state.temp_user_data = {
                        "first_name": first_name,
                        "last_name": last_name,
                        "username": username,
                        "password": password,
                        "totp_secret": totp_secret
                    }
                    
                    # Go to QR setup page
                    go_to_qr_setup()
                    st.experimental_rerun()

# QR Code Setup Page
elif st.session_state.page == "qr_setup":
    if not st.session_state.temp_user_data:
        st.error("User data not found. Please sign up again.")
        if st.button("Back to Sign Up", key="back_to_signup_1"):
            go_to_signup()
            st.experimental_rerun()
    else:
        with st.container():
            st.subheader("Set up Two-Factor Authentication")
            
            # Display user information
            st.info(f"Your username will be: **{st.session_state.temp_user_data['username']}**")
            st.markdown("Please scan this QR code with your Google Authenticator app.")
            
            # Generate TOTP URI
            totp_uri = pyotp.TOTP(st.session_state.temp_user_data['totp_secret']).provisioning_uri(
                name=st.session_state.temp_user_data['username'],
                issuer_name="SecureLogin"
            )
            
            # Generate and display QR code
            qr_code_b64 = generate_qr_code(totp_uri)
            st.markdown(f'<div class="centered-text"><img src="data:image/png;base64,{qr_code_b64}" width="200"/></div>', 
                        unsafe_allow_html=True)
            
            # Verification code
            verification_code = st.text_input("Enter the 6-digit code from the app", key="verification_code")
            
            col1, col2 = st.columns([1, 2])
            
            with col1:
                verify_button = st.button("Verify and Complete Setup")
            
            with col2:
                if st.button("Back", key="back_from_qr"):
                    go_to_signup()
                    st.experimental_rerun()
            
            if verify_button:
                if not verification_code:
                    st.error("Please enter the verification code.")
                else:
                    # Verify TOTP code
                    totp = pyotp.TOTP(st.session_state.temp_user_data['totp_secret'])
                    if totp.verify(verification_code):
                        # Save user to database
                        conn = get_connection()
                        cur = conn.cursor()
                        try:
                            cur.execute(
                                """INSERT INTO users (first_name, last_name, username, password, totp_secret) 
                                   VALUES (%s, %s, %s, %s, %s) RETURNING id""",
                                (
                                    st.session_state.temp_user_data['first_name'],
                                    st.session_state.temp_user_data['last_name'],
                                    st.session_state.temp_user_data['username'],
                                    hash_password(st.session_state.temp_user_data['password']),
                                    st.session_state.temp_user_data['totp_secret']
                                )
                            )
                            user_id = cur.fetchone()[0]
                            conn.commit()
                            
                            # Set success message
                            st.session_state.auth_message = {
                                "type": "success",
                                "message": f"Account created successfully! Your username is {st.session_state.temp_user_data['username']}"
                            }
                            
                            # Clear temp data
                            st.session_state.temp_user_data = {}
                            
                            # Go to login page
                            go_to_login()
                            st.experimental_rerun()
                            
                        except psycopg2.errors.UniqueViolation:
                            st.error("Username already exists. Please try again.")
                        except Exception as e:
                            st.error(f"An error occurred: {e}")
                        finally:
                            cur.close()
                            conn.close()
                    else:
                        st.error("Invalid verification code. Please try again.")

# Dashboard Page
elif st.session_state.page == "dashboard":
    if "username" not in st.session_state:
        st.error("You are not logged in.")
        go_to_login()
        st.experimental_rerun()
    else:
        st.subheader(f"Welcome, {st.session_state.username}")
        
        # Get user details
        conn = get_connection()
        cur = conn.cursor()
        cur.execute(
            "SELECT first_name, last_name FROM users WHERE id = %s",
            (st.session_state.user_id,)
        )
        user_info = cur.fetchone()
        cur.close()
        conn.close()
        
        if user_info:
            first_name, last_name = user_info
            st.write(f"Name: {first_name} {last_name}")
        
        st.write("You have successfully logged in to the secure application.")
        
        # Simple dashboard content
        st.markdown("---")
        st.subheader("Dashboard Content")
        st.write("This is where your application content would go.")
        
        # Logout button
        if st.button("Logout"):
            # Clear session state
            for key in ["user_id", "username"]:
                if key in st.session_state:
                    del st.session_state[key]
            go_to_login()
            st.experimental_rerun()

# Display auth messages
if st.session_state.auth_message:
    if st.session_state.auth_message["type"] == "success":
        st.success(st.session_state.auth_message["message"])
    elif st.session_state.auth_message["type"] == "error":
        st.error(st.session_state.auth_message["message"])
    st.session_state.auth_message = None