from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.models import User
from django import forms
from app.models import *

class SignUpForm(UserCreationForm):
    email = forms.EmailField()

    class Meta:
        model = Profile
        fields = UserCreationForm.Meta.fields + ("email", )

    def save(self, commit=True):
        user = super().save(commit=False)
        user.role = 'DEFAULT'
        if commit:
            user.save()
            # create an InvestmentPortfolio for the new user
            InvestmentPortfolio.objects.create(user=user)
        return user


class LoginForm(AuthenticationForm):
    username = forms.CharField(widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Username'}))
    password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'Password'}))


class SecurityForm(forms.ModelForm):
    class Meta:
        model = Security
        fields = ['asset_type', 'asset_name', 'price']
        labels = {
            'asset_type': 'Тип актива',
            'asset_name': 'Название актива',
            'price': 'Цена',
        }

class PortfolioSecurityForm(forms.ModelForm):
    class Meta:
        model = PortfolioSecurity
        fields = ['portfolio', 'security', 'asset_quantity']
        labels = {
            'portfolio': 'Портфель',
            'security': 'Название актива',
            'asset_quantity': 'Количество',
        }


class DeleteSecurityForm(forms.Form):
    security = forms.ModelChoiceField(queryset=Security.objects.all(), label="Выберите актив для удаления")

class DeletePortfolioSecurityForm(forms.Form):
    portfoliosecurity = forms.ModelChoiceField(queryset=PortfolioSecurity.objects.all(), label="Выберите актив для удаления")