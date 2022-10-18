from django.core.mail import EmailMessage

''' send_mail function is for sending an email '''

class Utils:
    @staticmethod
    def send_email(data):
        email = EmailMessage(subject=data['email_subject'], body=data['email_body'], to=[data['to_email']])
        email.content_subtype ="html"
        email.send()
    
