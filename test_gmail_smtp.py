import smtplib
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

EMAIL_USER = os.getenv("EMAIL_USER")  # Get email from .env
EMAIL_PASS = os.getenv("EMAIL_PASS")  # Get app password from .env

try:
    print("🔄 Connecting to Gmail SMTP server...")
    with smtplib.SMTP("smtp.gmail.com", 587) as server:
        server.set_debuglevel(1)  # Show detailed logs
        server.starttls()  # Secure connection
        server.login(EMAIL_USER, EMAIL_PASS)  # Try logging in
        print("✅ SMTP Login Successful! Your credentials are correct.")
except Exception as e:
    print(f"❌ SMTP Login Failed: {e}")
