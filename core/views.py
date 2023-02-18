from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import TemplateView


class TopView(TemplateView):
    template_name = 'top.html'


class SecretView(LoginRequiredMixin, TemplateView):
    template_name = 'secret.html'
