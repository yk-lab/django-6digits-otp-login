from django.contrib.auth.views import LogoutView
from django.urls import path

from .views import LoginView, VerifyOtpView

app_name = 'accounts'


urlpatterns = [
    path("login/", LoginView.as_view(), name="login"),
    path("logout/", LogoutView.as_view(), name="logout"),
    path("verify-otp/", VerifyOtpView.as_view(), name="verify-otp"),
]
