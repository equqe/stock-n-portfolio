# Generated by Django 5.1.2 on 2024-11-13 23:03

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Profile',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('username', models.CharField(max_length=64)),
                ('email', models.CharField(max_length=255)),
                ('password', models.CharField(max_length=255)),
                ('role', models.CharField(choices=[('Клиент', 'Клиент'), ('Менеджер', 'Менеджер'), ('Администратор', 'Администратор')], default='Клиент', max_length=50)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
        ),
        migrations.CreateModel(
            name='Security',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('asset_name', models.CharField(max_length=255)),
                ('asset_type', models.CharField(max_length=50)),
                ('price', models.DecimalField(decimal_places=2, max_digits=10)),
            ],
        ),
        migrations.CreateModel(
            name='InvestmentPortfolio',
            fields=[
                ('portfolio_id', models.AutoField(primary_key=True, serialize=False)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='app.Profile')),
            ],
        ),
        migrations.CreateModel(
            name='Notification',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('message', models.CharField(max_length=255)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='app.Profile')),
            ],
        ),
        migrations.CreateModel(
            name='PortfolioSecurity',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('asset_quantity', models.IntegerField()),
                ('portfolio', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='app.investmentportfolio')),
                ('security', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='app.security')),
            ],
        ),
        migrations.CreateModel(
            name='StockChart',
            fields=[
                ('chart_id', models.AutoField(primary_key=True, serialize=False)),
                ('chart_data', models.BinaryField()),
                ('stock_symbol', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='app.security')),
            ],
        ),
    ]
