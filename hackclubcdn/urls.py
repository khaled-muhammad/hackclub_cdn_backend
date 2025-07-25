"""
URL configuration for hackclubcdn project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, re_path, include

from fronty.views import FrontendAppView
from my_auth.views import slack_callback, temp_auth_code, update_password, fetch_me, CookieTokenRefreshView, logout_view, login_view

urlpatterns = [
    path('admin/', admin.site.urls),
    
    # Authentication endpoints
    path('api/slack/callback', slack_callback),
    path('api/auth/retrieve', temp_auth_code),
    path('api/auth/reset_password', update_password),
    path('api/auth/me', fetch_me),
    path('api/auth/refresh', CookieTokenRefreshView.as_view(), name='token_refresh'),
    path('api/auth/logout', logout_view),
    path('api/auth/login', login_view),
    path('', include('cdn.urls')),
    
    # Frontend (uncomment when ready)
    re_path(r'^(?!api/).*$', FrontendAppView.as_view()),
]