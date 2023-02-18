from __future__ import annotations

import dataclasses
from logging import getLogger
from typing import Any

from django.contrib.auth import REDIRECT_FIELD_NAME
from django.contrib.auth import login as auth_login
from django.contrib.auth.views import RedirectURLMixin
from django.http import HttpResponse, HttpResponseRedirect
from django.urls import reverse_lazy
from django.utils.decorators import method_decorator
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.debug import sensitive_post_parameters
from django.views.generic import FormView

from .forms import LoginForm, VerifyOtpForm
from .otp_utils import OTPSession, UserEmailOTPSigner

AUTH_LOGIN_SESSION_KEY = 'otp_auth_login'
AUTH_LOGIN_QUERY_KEY = 'login'


logger = getLogger(__name__)


class LoginView(FormView):
    redirect_authenticated_user = False
    redirect_field_name = REDIRECT_FIELD_NAME
    template_name = "registration/login.html"

    @method_decorator(sensitive_post_parameters())
    @method_decorator(csrf_protect)
    @method_decorator(never_cache)
    def dispatch(self, request, *args, **kwargs):
        if self.redirect_authenticated_user and self.request.user.is_authenticated:  # noqa: E501
            redirect_to = self.get_success_url()
            if redirect_to == self.request.path:
                raise ValueError(
                    "Redirection loop for authenticated user detected. Check that "  # noqa: E501
                    "your LOGIN_REDIRECT_URL doesn't point to a login page."
                )
            return HttpResponseRedirect(redirect_to)
        return super().dispatch(request, *args, **kwargs)

    def get_form_class(self) -> type[LoginForm]:
        return LoginForm

    def get_success_url(self):
        redirect_to = self.request.POST.get(
            self.redirect_field_name,
            self.request.GET.get(self.redirect_field_name)
        ) if self.request else None

        session = self.request.session[AUTH_LOGIN_SESSION_KEY] or {}
        signature = session.get('auth_id') or ''
        url = f'{reverse_lazy("accounts:verify-otp")}'
        url += f'?{AUTH_LOGIN_QUERY_KEY}={signature}'

        if redirect_to:
            url += f"&{self.redirect_field_name}={redirect_to}"
        return url

    def form_valid(self, form: LoginForm):
        form.send_mail()
        if (email_device := form.email_device) and (user := form.user):
            self.request.session[AUTH_LOGIN_SESSION_KEY] = dataclasses.asdict(
                OTPSession(**{
                    'device_pk': email_device.pk,
                    'user_pk': user.pk,
                    'auth_id': UserEmailOTPSigner().signature(email_device)
                })
            )
        return super().form_valid(form)


class VerifyOtpView(RedirectURLMixin, FormView):
    form_class = VerifyOtpForm
    template_name = "registration/verify-otp.html"
    next_page = reverse_lazy('top')

    def redirect_to_login(self):
        return HttpResponseRedirect(reverse_lazy('accounts:login'))

    def dispatch(self, request, *args, **kwargs):
        try:
            session = self.request.session[AUTH_LOGIN_SESSION_KEY]
            if not session:
                return self.redirect_to_login()

            self.session = OTPSession(**session)
        except Exception as e:
            logger.warn(e)
            return self.redirect_to_login()
        return super().dispatch(request, *args, **kwargs)

    def get_initial(self) -> dict[str, Any]:
        return {
            'auth_id': self.session.auth_id,
            **super().get_initial(),
        }

    def get_form_kwargs(self) -> dict[str, Any]:
        return {
            'session': self.session,
            **super().get_form_kwargs(),
        }

    def form_valid(self, form: VerifyOtpForm) -> HttpResponse:
        auth_login(self.request, form.user)
        del self.request.session[AUTH_LOGIN_SESSION_KEY]
        return super().form_valid(form)
