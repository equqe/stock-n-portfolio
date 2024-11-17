from django.contrib.auth.views import *
from django.contrib import admin
from django.urls import path
from app.views import *

urlpatterns = [
    path('', redirect_to_dashboard),
    path('op/admin/', admin.site.urls),
    # client
    path('client/dashboard/', index_client),
    path('client/portfolio/', portfolio_client),
    path('client/settings/', client_settings),
    path('client/notifications/', notifications),
    # manager
    path('manager/dashboard/', index_manager),
    path('manager/settings/', settings, name='settings'),
    path('manager/portfoliosecurity/add/', add_to_portfolio),
    path('manager/portfoliosecurity/remove/', remove_from_portfolio),
    path('manager/portfoliosecurity/info/<int:portfoliosecurity_id>/', portfoliosecurity_info, name='portfoliosecurity_info'),
    path('manager/portfolio/info/<int:portfolio_id>/', portfolio_info, name='portfolio_info'),
    path('manager/security/info/<int:security_id>/', security_info, name='security_info'),
    path('manager/analysis/', analysis, name='analysis'),
    path('manager/analysis/stock/', stock_analysis, name='stock_analysis_manager'),
    path('manager/analysis/portfolio/', portfolio_analysis, name='portfolio_analysis_manager'),
    # admin
    path('admin/dashboard/', index_admin),
    path('admin/users/', user_info_view, name='user_info'),
    path('admin/security/add/', add_security, name='add_security'),
    path('admin/security/all/', all_securities, name='all_securities'),
    path('admin/security/remove/', remove_security, name='remove_security'),
    path('admin/security/edit/<int:security_id>/', edit_security, name='edit_security'),
    path('admin/security/delete/<int:security_id>/', delete_security, name='delete_security'),
    path('admin/security/info/<int:security_id>/', get_security_info, name='get_security_info'),
    path('admin/analysis/', analysis_admin, name='analysis'),
    path('admin/analysis/stock/', stock_analysis_admin, name='stock_analysis'),
    path('admin/analysis/portfolio/', portfolio_analysis_admin, name='portfolio_analysis'),
    # password reset
    path('password_reset/', PasswordResetView.as_view(), name='password_reset'),
    path('password_reset/done/', PasswordResetDoneView.as_view(), name='password_reset_done'),
    path('reset/<uidb64>/<token>/', PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('reset/done/', PasswordResetCompleteView.as_view(), name='password_reset_complete'),
    # auth
    path('register/', signup),
    path('login/', signin),
    path('logout/', user_logout),
    # chat
    path('client/chat/', chat_client, name='chat_client'),
    path('manager/chat/', chat_manager, name='chat_manager'),
    path('manager/chat/<int:client_id>/', chat_manager_client, name='chat_manager_client'),
    path('send_message/', send_message, name='send_message'),
    # test
    # path('send-test-email/', send_test_email, name='send_test_email'),
]
