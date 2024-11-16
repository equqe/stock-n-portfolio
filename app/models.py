from django.db import models
from django.contrib.auth.models import AbstractUser
from django.contrib.auth import get_user_model

class Profile(AbstractUser):
    DEFAULT = "DEFAULT"
    MANAGER = "MANAGER"
    ADMIN = "ADMIN"

    ROLE_CHOICES = [
        (DEFAULT, "Клиент"),
        (MANAGER, "Менеджер"),
        (ADMIN, "Администратор")
    ]

    role = models.CharField(
        max_length=50, 
        choices=ROLE_CHOICES, 
        default=DEFAULT
    )
    receive_notifications = models.BooleanField(default=True)

class ChatMessage(models.Model):
    client = models.ForeignKey(get_user_model(), related_name='client_messages', on_delete=models.CASCADE)
    manager = models.ForeignKey(get_user_model(), related_name='manager_messages', on_delete=models.CASCADE, null=True, blank=True)
    message = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f'{self.client} to {self.manager}: {self.message}'

class Notification(models.Model):
    user = models.ForeignKey(Profile, on_delete=models.CASCADE)
    message = models.CharField(max_length=255, null=False)
    created_at = models.DateTimeField(auto_now_add=True)

class Security(models.Model):
    STK = "STK"
    BND = "BND"
    BOE = "BOE"
    CHK = "CHK"
    SHR = "SHR"

    SCTYPE_CHOICES = [
        (STK, "Акция"),
        (BND, "Облигация"),
        (BOE, "Вексель"),
        (CHK, "Чек"),
        (SHR, "Пай")
    ]

    asset_type = models.CharField(
        max_length=50, 
        choices=SCTYPE_CHOICES
    )

    asset_name = models.CharField(max_length=255, null=False)
    price = models.DecimalField(max_digits=10, decimal_places=2, null=False)

class StockChart(models.Model):
    chart_id = models.AutoField(primary_key=True)
    stock_symbol = models.ForeignKey(Security, on_delete=models.CASCADE)
    chart_data = models.BinaryField()

class InvestmentPortfolio(models.Model):
    portfolio_id = models.AutoField(primary_key=True)
    user = models.ForeignKey(Profile, on_delete=models.CASCADE)

class PortfolioSecurity(models.Model):
    portfolio = models.ForeignKey(InvestmentPortfolio, on_delete=models.CASCADE)
    security = models.ForeignKey(Security, on_delete=models.CASCADE)
    asset_quantity = models.IntegerField(null=False)
