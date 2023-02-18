from django.urls import path

from .views import SecretView, TopView

urlpatterns = [
    path("", TopView.as_view(), name="top"),
    path("secret", SecretView.as_view(), name="secret"),
]
