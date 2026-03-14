from argon2 import PasswordHasher
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import os
from dotenv import load_dotenv
from htmlmessage import mainHtml
import secrets

ph = PasswordHasher()
def hashedpassword(password):
    hashed=ph.hash(password)
    return hashed

def verifyHashed(hashedpassword,password):
    value=ph.verify(hashedpassword,password)
    return value




load_dotenv()

def send_email(receiver: str, subject: str, body: str):
    """
    Sends an email using Gmail SMTP.

    Args:
        sender (str): Sender email address.
        receiver (str): Receiver email address.
        subject (str): Email subject line.
        body (str): Email body text.
    """
    password = os.getenv("PASSWORD")  # Make sure PASSWORD exists in .env
    email = os.getenv("SENDER_EMAIL")  # Make sure SENDER_EMAIL exists in .env

    # Create email structure
    message = MIMEMultipart()
    message["From"] = email
    message["To"] = receiver
    message["Subject"] = subject
    message.attach(MIMEText(body, "plain"))

    # Send email
    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(email, password)
            server.sendmail(email, receiver, message.as_string())
            print("Email sent successfully")

    except Exception as e:
        print("Email failed:", e)



load_dotenv()

def send_html_email(receiver: str, subject: str, id: str):
    """
    Sends an HTML email using Gmail SMTP.

    Args:
        sender (str): Sender email address.
        receiver (str): Receiver email address.
        subject (str): Email subject line.
        html_content (str): HTML body (supports tags, CSS, links, buttons).
    """
    password = os.getenv("PASSWORD")  # Get app password from .env
    email = os.getenv("SENDER_EMAIL")

    # Email structure
    message = MIMEMultipart("alternative")  
    message["From"] = email
    message["To"] = receiver
    message["Subject"] = subject

    # Attach the HTML to the email
    message.attach(MIMEText(mainHtml(id), "html"))

    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(email, password)
            server.sendmail(email, receiver, message.as_string())
            print("HTML email sent successfully!")

    except Exception as e:
        print("Failed to send email:", e)


# generate OTP
def generate_otp():
    """Generate a secure 6-digit OTP code."""
    return str(secrets.randbelow(1000000)).zfill(6)
