# Generated by Django 5.1.2 on 2024-11-14 17:47

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0003_alter_profile_options_alter_profile_managers_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='security',
            name='asset_type',
            field=models.CharField(choices=[('Акция', 'Акция'), ('Облигация', 'Облигация'), ('Вексель', 'Вексель'), ('Чек', 'Чек'), ('Пай', 'Пай')], max_length=50),
        ),
    ]
