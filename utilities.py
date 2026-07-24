from argon2 import PasswordHasher
import os
from dotenv import load_dotenv
import secrets
import resend

ph = PasswordHasher()

def hashedpassword(password):
    return ph.hash(password)

def verifyHashed(hashedpassword, password):
    try:
        return ph.verify(hashedpassword, password)
    except Exception:
        return False

load_dotenv()

resend.api_key = os.getenv("RESEND_API_KEY")

def send_email(receiver: str, subject: str, html: str):
    params: resend.Emails.SendParams = {
        "from": os.getenv("SENDER_EMAIL"),
        "to": [receiver],
        "subject": subject,
        "html": html,
    }
    return resend.Emails.send(params)

def generate_otp():
    return str(secrets.randbelow(1000000)).zfill(6)
