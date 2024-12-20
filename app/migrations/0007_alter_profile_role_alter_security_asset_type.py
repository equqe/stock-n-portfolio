# Generated by Django 5.1.2 on 2024-11-14 21:50

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0006_delete_chatmessage'),
    ]

    operations = [
        migrations.AlterField(
            model_name='profile',
            name='role',
            field=models.CharField(choices=[('DEFAULT', 'Клиент'), ('MANAGER', 'Менеджер'), ('ADMIN', 'Администратор')], default='DEFAULT', max_length=50),
        ),
        migrations.AlterField(
            model_name='security',
            name='asset_type',
            field=models.CharField(choices=[('STK', 'Акция'), ('BND', 'Облигация'), ('BOE', 'Вексель'), ('CHK', 'Чек'), ('SHR', 'Пай')], max_length=50),
        ),
    ]
