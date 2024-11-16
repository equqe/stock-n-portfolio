from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from app.models import *
from django.contrib.auth.models import User

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


class DeleteSecurityForm(forms.Form):
    security = forms.ModelChoiceField(queryset=Security.objects.all(), label="Выберите актив для удаления")