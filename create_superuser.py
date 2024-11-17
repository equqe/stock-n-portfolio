import os
import django
from django.contrib.auth import get_user_model

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'stock.settings')
django.setup()

Profile = get_user_model()

username = 'arsennazranov'
email = 'arsennazranov@gmail.com'
password = 'arsennazranov'

if not Profile.objects.filter(username=username).exists():
    Profile.objects.create_superuser(username, email, password)
