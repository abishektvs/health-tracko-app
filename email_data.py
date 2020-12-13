from email.mime.text import MIMEText
from email.message import EmailMessage
from smtplib import SMTP
import configparser

config = configparser.ConfigParser()
config.read(r"..\confidential.ini")

def email(to_email, subject, message, body):
    from_email = "abishektvs174@gmail.com"
    from_password = config["email_smtp"]["password"]
 
    if body == 'Text':
        msg = MIMEText(message, 'html')
    else:
        msg = EmailMessage()
        msg.set_content("Your BMI report document has been attached")
        msg.add_attachment(open(body, "r").read(), filename= body)
    
    msg["Subject"] = subject
    msg["To"] = to_email
    msg["From"] = from_email

    gmail = SMTP('smtp.gmail.com', 587)
    gmail.ehlo()
    gmail.starttls()
    gmail.login(from_email, from_password)
    gmail.send_message(msg)

def send_otp(otp, requested_mail):
    to_email = requested_mail

    subject = "[ Health Track ] Resetting New Password"
    message = 'Your OTP to reset password is {} ,  OTP will expire in 4 minutes'.format(otp)

    email(to_email, subject, message, body = 'Text')

def send_bmidata_tomail(to_email, bmidata_filename, username):
    subject = "[ Health Track ] BMI data tracks"
    message = 'Dear {}, here is your BMI track'.format(username)

    email(to_email, subject, message, body = bmidata_filename)

def send_signup_email_verification(to_email, otp):
    subject = "[ Health Track ] Email verification"
    message = 'Your email verification otp is {} , OTP will expire in 4 minutes'.format(otp)

    email(to_email, subject, message, body = 'Text')
