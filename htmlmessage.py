def mainHtml(token):
    html = f"""
    <html>
    <body style="font-family: Arial; background: #f6f6f6; padding: 20px;">
        <div style="max-width: 500px; margin: auto; background: white; padding: 20px; border-radius: 10px;">
        <h2 style="color: #333;">Welcome to Revival Network Commission</h2>
        <p>Hello!</p>
        <p>Thank you for signing up. Please click the button below to verify your account.</p>

        <a href="http://127.0.0.1:8000/verify?token={token}"
            style="
                display: inline-block;
                background: #150f33;
                color: white;
                padding: 12px 20px;
                text-decoration: none;
                border-radius: 5px;
                margin-top: 15px;
            ">
            Verify Account
        </a>

        <p style="margin-top: 25px; color: #777;">
            If you didn't create an account, please ignore this email.
        </p>
        </div>
    </body>
    </html>
    """
    return html