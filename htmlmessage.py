def otp_html(otp: str):
    return f"""
    <html>
    <body style="font-family: Arial, sans-serif; background: #f6f6f6; padding: 20px;">
        <div style="max-width: 500px; margin: auto; background: white; padding: 30px; border-radius: 10px; text-align: center;">
            <h2 style="color: #150f33;">Revival Network Commission</h2>
            <p style="color: #555; font-size: 16px;">Your verification code is:</p>
            <div style="font-size: 36px; font-weight: bold; letter-spacing: 8px; color: #150f33; margin: 25px 0;">
                {otp}
            </div>
            <p style="color: #999; font-size: 13px;">This code expires in 10 minutes. If you didn't create an account, please ignore this email.</p>
        </div>
    </body>
    </html>
    """
