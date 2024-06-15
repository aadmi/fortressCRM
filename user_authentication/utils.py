import random
from django.core.mail import EmailMessage
from django.template.loader import render_to_string
from django.utils.html import strip_tags

from fortressCRM.helper_functions import api_log


def generate_otp():
    return str(random.randint(100000, 999999))


def send_verification_email(email, otp):
    subject = "Verify Your Email Address"
    template_name = "email_verification.html"
    context = {"otp": otp}

    html_content = render_to_string(template_name, context)
    text_content = strip_tags(html_content)

    msg = EmailMessage(subject, text_content, to=[email])
    msg.content_subtype = "html"
    api_log(msg=f"email sent: {msg.send()}")
    msg.send()