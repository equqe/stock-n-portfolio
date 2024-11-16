from django.shortcuts import render, redirect, get_object_or_404
from django.http import JsonResponse
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.mixins import PermissionRequiredMixin, LoginRequiredMixin
from django.contrib.auth.decorators import login_required, permission_required, user_passes_test
from django.core.mail import send_mail
from stock.forms import *
from .models import *
from stock.decorators import role_required
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from django.db.models import Count
import matplotlib.pyplot as plt
import io
import base64
import logging

def is_anonymous(user):
    return user.is_anonymous

def send_test_email():
    subject = 'Test Email'
    message = 'This is a test email.'
    from_email = '7f52db001@smtp-brevo.com'
    to_list = ['oaouzc@gmail.com']
    try:
        send_mail(subject, message, from_email, to_list, fail_silently=False)
        logger.info("Test email sent successfully.")
    except Exception as e:
        logger.error(f"Failed to send test email: {e}")

# auth
logger = logging.getLogger(__name__)

@user_passes_test(lambda u: u.is_anonymous, login_url='/')
def signup(request):
    if request.method == 'POST':
        form = SignUpForm(request.POST)
        if form.is_valid():
            user = form.save()
            if user is not None:
                login(request, user)
                subject = 'Добро пожаловать!'
                message = f'Здравствуйте, {user.username}. Спасибо за регистрацию на нашем сайте. Приятного пользования.'
                from_email = 'webmaster@localhost'
                to_list = [user.email]
                try:
                    send_mail(subject, message, from_email, to_list)
                    logger.info(f"Email sent to {user.email}")
                except Exception as e:
                    logger.error(f"Failed to send email: {e}")

                if user.role == 'DEFAULT':
                    return redirect('/client/dashboard')
                elif user.role == 'MANAGER':
                    return redirect('/manager/dashboard')
                elif user.role == 'ADMIN':
                    return redirect('/admin/dashboard')
            else:
                return HttpResponse('405. Invalid credentials.', status=405)
    else:
        form = SignUpForm()
    return render(request, 'register.html', {'form': form})

@user_passes_test(is_anonymous, login_url='/')
def signin(request):
    if request.method == 'POST':
        form = LoginForm(request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(request, username=username, password=password)
            if user is not None:
                login(request, user)
                if user.role == 'DEFAULT':
                    return redirect('/client/dashboard')
                elif user.role == 'MANAGER':
                    return redirect('/manager/dashboard')
                elif user.role == 'ADMIN':
                    return redirect('/admin/dashboard')
            else:
                return HttpResponse('405. Invalid credentials.')
    else:
        form = LoginForm()
    return render(request, 'login.html', {'form': form})

@login_required
def user_logout(request):
    if request.method == 'POST':
        logout(request)
        return redirect('/login')
    return render(request, 'logout.html')

# redirect
@login_required
def redirect_to_dashboard(request):
    if request.user.is_authenticated:
        if request.user.role == Profile.ADMIN:
            return redirect('/admin/dashboard')
        elif request.user.role == Profile.MANAGER:
            return redirect('/manager/dashboard')
        else:
            return redirect('/client/dashboard')
    else:
        return redirect('login')

# client
@role_required(Profile.DEFAULT)
def index_client(request):
    context = {
        'username': request.user.username
    }
    return render(request, 'index_client.html', context)

@role_required(Profile.DEFAULT)
def portfolio_client(request):
    investments = Security.objects.all()
    context = {
        'username': request.user.username,
        'investments': investments
    }
    return render(request, 'portfolio.html', context)

# manager
@role_required(Profile.MANAGER)
def index_manager(request):
    return render(request, 'index_manager.html')

@login_required
def settings(request):
    if request.method == 'POST':
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        receive_notifications = request.POST.get('receive_notifications') == 'on'
        user = request.user
        user.first_name = first_name
        user.last_name = last_name
        user.receive_notifications = receive_notifications
        user.save()
        return redirect('/manager/settings/')
    return render(request, 'settings.html', {'user': request.user})

# admin
@role_required(Profile.ADMIN)
def index_admin(request):
    return render(request, 'index_admin.html')

@role_required(Profile.ADMIN)
def user_info_view(request):
    users = Profile.objects.all().order_by('id')
    return render(request, 'user_info.html', {'users': users})

@role_required(Profile.ADMIN)
def add_security(request):
    if request.method == 'POST':
        form = SecurityForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('user_info')
    else:
        form = SecurityForm()
    return render(request, 'add_stocks.html', {'form': form})

@role_required(Profile.ADMIN)
def edit_security(request, security_id):
    security = get_object_or_404(Security, id=security_id)
    if request.method == 'POST':
        form = SecurityForm(request.POST, instance=security)
        if form.is_valid():
            form.save()
            return redirect('user_info')
    else:
        form = SecurityForm(instance=security)
    return render(request, 'edit_security.html', {'form': form})

@role_required(Profile.ADMIN)
def delete_security(request, security_id):
    security = get_object_or_404(Security, id=security_id)
    if request.method == 'POST':
        security.delete()
        return redirect('user_info')
    return render(request, 'delete_security.html', {'security': security})

@role_required(Profile.ADMIN)
def remove_security(request):
    if request.method == 'POST':
        form = DeleteSecurityForm(request.POST)
        if form.is_valid():
            security = form.cleaned_data['security']
            security.delete()
            return redirect('user_info')
    else:
        form = DeleteSecurityForm()
    return render(request, 'remove_stocks.html', {'form': form})

def get_security_info(request, security_id):
    security = get_object_or_404(Security, id=security_id)
    data = {
        'asset_name': security.asset_name,
        'asset_type': security.get_asset_type_display(),
        'price': security.price
    }
    return JsonResponse(data)

# chat

@login_required
def chat_client(request):
    user = request.user
    messages = ChatMessage.objects.filter(client=user).order_by('timestamp')
    return render(request, 'chat_client.html', {'messages': messages})

@login_required
def chat_manager(request):
    user = request.user
    clients = get_user_model().objects.filter(role='DEFAULT')
    return render(request, 'chat_manager.html', {'clients': clients})

@login_required
def chat_manager_client(request, client_id):
    user = request.user
    client = get_object_or_404(get_user_model(), id=client_id)
    messages = ChatMessage.objects.filter(client=client).order_by('timestamp')
    return render(request, 'chat_manager_client.html', {'messages': messages, 'client': client})

@login_required
def send_message(request):
    if request.method == 'POST':
        message_text = request.POST.get('message')
        client_id = request.POST.get('client_id')
        client = get_object_or_404(get_user_model(), id=client_id)
        ChatMessage.objects.create(client=client, manager=request.user, message=message_text)

        managers = get_user_model().objects.filter(role='MANAGER', receive_notifications=True)
        for manager in managers:
            notification = f"Новое сообщение от {client.username}"
            channel_layer = get_channel_layer()
            async_to_sync(channel_layer.group_send)(
                "notifications_group",
                {
                    'type': 'send_notification',
                    'message': notification
                }
            )

        if request.user.role == 'DEFAULT':
            return redirect('chat_client')
        else:
            return redirect('chat_manager_client', client_id=client.id)

# analysis
@login_required
def analysis(request):
    return render(request, 'analysis.html')
    
@login_required
def analysis_admin(request):
    return render(request, 'analysis_admin.html')

@login_required
def stock_analysis(request):
    securities = Security.objects.all()
    asset_types = securities.values('asset_type').annotate(count=Count('asset_type'))

    fig, ax = plt.subplots()
    ax.pie(asset_types.values_list('count', flat=True), labels=asset_types.values_list('asset_type', flat=True), autopct='%1.1f%%')
    ax.set_title('Анализ акций')
    fig.patch.set_facecolor('#e0ebff')
    ax.legend(asset_types.values_list('asset_type', flat=True), loc="center left", bbox_to_anchor=(1, 0.5))

    buf = io.BytesIO()
    plt.savefig(buf, format='png')
    buf.seek(0)
    image_png = buf.getvalue()
    buf.close()

    graphic = base64.b64encode(image_png).decode('utf-8')

    return render(request, 'stock_analysis.html', {'graphic': graphic})

@login_required
def portfolio_analysis(request):
    users = Profile.objects.filter(role='DEFAULT')
    if request.method == 'POST':
        user_id = request.POST.get('user_id')
        user = get_object_or_404(Profile, id=user_id)
        portfolio = get_object_or_404(InvestmentPortfolio, user=user)
        portfolio_securities = PortfolioSecurity.objects.filter(portfolio=portfolio)
        asset_types = portfolio_securities.values('security__asset_type').annotate(count=Count('security__asset_type'))

        fig, ax = plt.subplots()
        ax.pie(asset_types.values_list('count', flat=True), labels=asset_types.values_list('security__asset_type', flat=True), autopct='%1.1f%%')
        ax.set_title('Анализ портфеля')
        fig.patch.set_facecolor('#e0ebff')
        ax.legend(asset_types.values_list('security__asset_type', flat=True), loc="center left", bbox_to_anchor=(1, 0.5))

        buf = io.BytesIO()
        plt.savefig(buf, format='png')
        buf.seek(0)
        image_png = buf.getvalue()
        buf.close()

        graphic = base64.b64encode(image_png).decode('utf-8')

        return render(request, 'portfolio_analysis.html', {'graphic': graphic, 'users': users})

    return render(request, 'portfolio_analysis.html', {'users': users})

@login_required
def stock_analysis_admin(request):
    securities = Security.objects.all()
    asset_types = securities.values('asset_type').annotate(count=Count('asset_type'))

    fig, ax = plt.subplots()
    ax.pie(asset_types.values_list('count', flat=True), labels=asset_types.values_list('asset_type', flat=True), autopct='%1.1f%%')
    ax.set_title('Анализ акций')
    fig.patch.set_facecolor('#e0ebff')
    ax.legend(asset_types.values_list('asset_type', flat=True), loc="center left", bbox_to_anchor=(1, 0.5))

    buf = io.BytesIO()
    plt.savefig(buf, format='png')
    buf.seek(0)
    image_png = buf.getvalue()
    buf.close()

    graphic = base64.b64encode(image_png).decode('utf-8')

    return render(request, 'stock_analysis_admin.html', {'graphic': graphic})

@login_required
def portfolio_analysis_admin(request):
    users = Profile.objects.filter(role='DEFAULT')
    if request.method == 'POST':
        user_id = request.POST.get('user_id')
        user = get_object_or_404(Profile, id=user_id)
        portfolio = get_object_or_404(InvestmentPortfolio, user=user)
        portfolio_securities = PortfolioSecurity.objects.filter(portfolio=portfolio)
        asset_types = portfolio_securities.values('security__asset_type').annotate(count=Count('security__asset_type'))

        fig, ax = plt.subplots()
        ax.pie(asset_types.values_list('count', flat=True), labels=asset_types.values_list('security__asset_type', flat=True), autopct='%1.1f%%')
        ax.set_title('Анализ портфеля')
        fig.patch.set_facecolor('#e0ebff')
        ax.legend(asset_types.values_list('security__asset_type', flat=True), loc="center left", bbox_to_anchor=(1, 0.5))

        buf = io.BytesIO()
        plt.savefig(buf, format='png')
        buf.seek(0)
        image_png = buf.getvalue()
        buf.close()

        graphic = base64.b64encode(image_png).decode('utf-8')

        return render(request, 'portfolio_analysis_admin.html', {'graphic': graphic, 'users': users})

    return render(request, 'portfolio_analysis_admin.html', {'users': users})