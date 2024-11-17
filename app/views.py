from django.contrib.auth.decorators import login_required, permission_required, user_passes_test
from django.contrib.auth.mixins import PermissionRequiredMixin, LoginRequiredMixin
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.http import JsonResponse, HttpResponse 
from channels.layers import get_channel_layer
from stock.decorators import role_required
from asgiref.sync import async_to_sync
from django.core.mail import send_mail
from django.db.models import Count
import matplotlib.pyplot as plt
from stock.forms import *
from .models import *
import logging
import base64
import io

def is_anonymous(user):
    return user.is_anonymous

# test new smtp servers
# def send_test_email(request):
#     subject = 'Test Email'
#     message = 'This is a test email.'
#     from_email = 'MS_KK1T99@trial-3z0vklo1o9vg7qrx.mlsender.net'
#     to_list = ['YOURMAIL@YOURDOMAIN']
#     try:
#         send_mail(subject, message, from_email, to_list, fail_silently=False)
#         logger.info("Test email sent successfully.")
#         return HttpResponse("Test email sent successfully.")
#     except Exception as e:
#         logger.error(f"Failed to send test email: {e}")
#         return HttpResponse("Failed to send test email.", status=500)

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
    return render(request, 'registration/register.html', {'form': form})

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
    return render(request, 'registration/login.html', {'form': form})

@login_required
def user_logout(request):
    if request.method == 'POST':
        logout(request)
        return redirect('/login')
    return render(request, 'registration/logout.html')

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
    return render(request, 'client/index_client.html', context)

@role_required(Profile.DEFAULT)
def notifications(request):
    notifications = Notification.objects.filter(user=request.user).order_by('created_at')
    context = {
        'username': request.user.username,
        'notifications': notifications
    }
    return render(request, 'client/notifications.html', context)

@role_required(Profile.DEFAULT)
def portfolio_client(request):
    portfolio, created = InvestmentPortfolio.objects.get_or_create(user=request.user)
    portfolio_securities = PortfolioSecurity.objects.filter(portfolio=portfolio)

    context = {
        'username': request.user.username,
        'portfolio_securities': portfolio_securities
    }
    return render(request, 'client/portfolio.html', context)

@role_required(Profile.DEFAULT)
def client_settings(request):
    if request.method == 'POST':
        context = {
            'username': request.user.username
        }
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        user = request.user
        user.first_name = first_name
        user.last_name = last_name
        user.save()
        return redirect('/client/settings/')
    return render(request, 'client/client_settings.html', {'user': request.user})

# manager
@role_required(Profile.MANAGER)
def index_manager(request):
    context = {
        'username': request.user.username
    }
    return render(request, 'manager/index_manager.html')

@role_required(Profile.MANAGER)
def settings(request):
    context = {
        'username': request.user.username
    }
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
    return render(request, 'manager/settings.html', {'user': request.user})

@role_required(Profile.MANAGER)
def add_to_portfolio(request):
    context = {
        'username': request.user.username
    }
    if request.method == 'POST':
        form = PortfolioSecurityForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('/')
    else:
        form = PortfolioSecurityForm()
    return render(request, 'manager/add_to_portfolio.html', {'form': form})

@role_required(Profile.MANAGER)
def remove_from_portfolio(request):
    context = {
        'username': request.user.username
    }
    if request.method == 'POST':
        form = DeletePortfolioSecurityForm(request.POST)
        if form.is_valid():
            portfoliosecurity = form.cleaned_data['portfoliosecurity']
            portfoliosecurity.delete()
            return redirect('/')
    else:
        form = DeletePortfolioSecurityForm()
    return render(request, 'manager/remove_from_portfolio.html', {'form': form})

@role_required(Profile.MANAGER)
def portfoliosecurity_info(request, portfoliosecurity_id):
    portfoliosecurity = PortfolioSecurity.objects.get(id=portfoliosecurity_id)
    data = {
        'user_id': portfoliosecurity.portfolio.user.id,
        'username': portfoliosecurity.portfolio.user.username,
        'first_name': portfoliosecurity.portfolio.user.first_name,
        'last_name': portfoliosecurity.portfolio.user.last_name,
        'asset_type': portfoliosecurity.security.get_asset_type_display(),
        'asset_name': portfoliosecurity.security.asset_name,
        'price': portfoliosecurity.security.price,
    }
    return JsonResponse(data)

@role_required(Profile.MANAGER)
def portfolio_info(request, portfolio_id):
    portfolio = InvestmentPortfolio.objects.get(portfolio_id=portfolio_id)
    data = {
        'user_id': portfolio.user.id,
        'username': portfolio.user.username,
        'first_name': portfolio.user.first_name,
        'last_name': portfolio.user.last_name,
    }
    return JsonResponse(data)

@role_required(Profile.MANAGER)
def security_info(request, security_id):
    security = Security.objects.get(id=security_id)
    data = {
        'asset_type': security.get_asset_type_display(),
        'asset_name': security.asset_name,
        'price': security.price,
    }
    return JsonResponse(data)

# admin
@role_required(Profile.ADMIN)
def index_admin(request):
    context = {
        'username': request.user.username
    }
    return render(request, 'admin/index_admin.html')

@role_required(Profile.ADMIN)
def user_info_view(request):
    context = {
        'username': request.user.username
    }
    users = Profile.objects.all().order_by('id')
    return render(request, 'admin/user_info.html', {'users': users})

@role_required(Profile.ADMIN)
def add_security(request):
    context = {
        'username': request.user.username
    }
    if request.method == 'POST':
        form = SecurityForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('user_info')
    else:
        form = SecurityForm()
    return render(request, 'admin/add_stocks.html', {'form': form})

@role_required(Profile.ADMIN)
def edit_security(request, security_id):
    context = {
        'username': request.user.username
    }
    security = get_object_or_404(Security, id=security_id)
    if request.method == 'POST':
        form = SecurityForm(request.POST, instance=security)
        if form.is_valid():
            form.save()
            return redirect('user_info')
    else:
        form = SecurityForm(instance=security)
    return render(request, 'admin/edit_security.html', {'form': form})

@role_required(Profile.ADMIN)
def delete_security(request, security_id):
    context = {
        'username': request.user.username
    }
    security = get_object_or_404(Security, id=security_id)
    if request.method == 'POST':
        security.delete()
        return redirect('user_info')
    return render(request, 'admin/delete_security.html', {'security': security})

@role_required(Profile.ADMIN)
def remove_security(request):
    context = {
        'username': request.user.username
    }
    if request.method == 'POST':
        form = DeleteSecurityForm(request.POST)
        if form.is_valid():
            security = form.cleaned_data['security']
            security.delete()
            return redirect('user_info')
    else:
        form = DeleteSecurityForm()
    return render(request, 'admin/remove_stocks.html', {'form': form})

@role_required(Profile.ADMIN)
def get_security_info(request, security_id):
    context = {
        'username': request.user.username
    }
    security = get_object_or_404(Security, id=security_id)
    data = {
        'asset_name': security.asset_name,
        'asset_type': security.get_asset_type_display(),
        'price': security.price
    }
    return JsonResponse(data)

# chat
@role_required(Profile.DEFAULT)
def chat_client(request):
    user = request.user
    messages = ChatMessage.objects.filter(client=user).order_by('timestamp')
    return render(request, 'client/chat_client.html', {'messages': messages})

@role_required(Profile.MANAGER)
def chat_manager(request):
    user = request.user
    clients = get_user_model().objects.filter(role='DEFAULT')
    return render(request, 'manager/chat_manager.html', {'clients': clients})

@role_required(Profile.MANAGER)
def chat_manager_client(request, client_id):
    user = request.user
    client = get_object_or_404(get_user_model(), id=client_id)
    messages = ChatMessage.objects.filter(client=client).order_by('timestamp')
    return render(request, 'manager/chat_manager_client.html', {'messages': messages, 'client': client})

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
@role_required(Profile.MANAGER)
def analysis(request):
    context = {
        'username': request.user.username
    }
    return render(request, 'manager/analysis.html')
    
@role_required(Profile.ADMIN)
def analysis_admin(request):
    context = {
        'username': request.user.username
    }
    return render(request, 'admin/analysis_admin.html')

@role_required(Profile.MANAGER)
def stock_analysis(request):
    context = {
        'username': request.user.username
    }
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

    return render(request, 'manager/stock_analysis.html', {'graphic': graphic})

@role_required(Profile.MANAGER)
def portfolio_analysis(request):
    context = {
        'username': request.user.username
    }
    users = Profile.objects.filter(role='DEFAULT')
    if request.method == 'POST':
        user_id = request.POST.get('user_id')
        user = get_object_or_404(Profile, id=user_id)

        portfolio, created = InvestmentPortfolio.objects.get_or_create(user=user)
        portfolio_securities = PortfolioSecurity.objects.filter(portfolio=portfolio)
        if not portfolio_securities.exists():
            context['error_message'] = 'У клиента отсутствуют активы.'
            return render(request, 'manager/portfolio_analysis.html', {'users': users, **context})
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

        return render(request, 'manager/portfolio_analysis.html', {'graphic': graphic, 'users': users})

    return render(request, 'manager/portfolio_analysis.html', {'users': users})

@role_required(Profile.ADMIN)
def stock_analysis_admin(request):
    context = {
        'username': request.user.username
    }
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

    return render(request, 'admin/stock_analysis_admin.html', {'graphic': graphic})

@role_required(Profile.ADMIN)
def portfolio_analysis_admin(request):
    context = {
        'username': request.user.username
    }
    users = Profile.objects.filter(role='DEFAULT')
    if request.method == 'POST':
        user_id = request.POST.get('user_id')
        user = get_object_or_404(Profile, id=user_id)

        portfolio, created = InvestmentPortfolio.objects.get_or_create(user=user)

        portfolio_securities = PortfolioSecurity.objects.filter(portfolio=portfolio)

        if not portfolio_securities.exists():
            context['error_message'] = 'У клиента отсутствуют активы.'
            return render(request, 'admin/portfolio_analysis_admin.html', {'users': users, **context})

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

        return render(request, 'admin/portfolio_analysis_admin.html', {'graphic': graphic, 'users': users})

    return render(request, 'admin/portfolio_analysis_admin.html', {'users': users})

@role_required(Profile.ADMIN)
def all_securities(request):
    securities = Security.objects.all()
    context = {
        'username': request.user.username,
        'securities': securities
    }
    return render(request, 'admin/all_securities.html', context)