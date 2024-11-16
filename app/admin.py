from django.contrib import admin
from .models import *

admin.site.register(Profile)
admin.site.register(ChatMessage)
admin.site.register(Notification)
admin.site.register(Security)
admin.site.register(StockChart)
admin.site.register(InvestmentPortfolio)
admin.site.register(PortfolioSecurity)