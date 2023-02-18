from __future__ import annotations

from logging import getLogger
from typing import Any

from django import forms
from django.contrib.auth import get_user_model
from django.core import validators
from django.core.exceptions import ObjectDoesNotExist, ValidationError
from django.db import connection
from django.forms import widgets
from django.http import HttpRequest
from django.utils.crypto import constant_time_compare
from django.utils.translation import gettext_lazy as _
from django_otp.plugins.otp_email.models import EmailDevice

from .otp_utils import OTPSession, UserEmailOTPSigner

logger = getLogger(__name__)


class LoginForm(forms.Form):
    user = None
    email_device = None

    field_name: str
    from_email = None

    error_messages = {
        "account_inactive": _("This account is currently inactive."),
        "email_mismatch": _("No loginable user found."),
    }

    def __init__(self, *args, **kwargs):
        self.request: HttpRequest | None = kwargs.pop("request", None)
        super().__init__(*args, **kwargs)
        self.field_name = self.field_name if hasattr(self, 'field_name')\
            else get_user_model().get_email_field_name()
        model_field = get_user_model()._meta.get_field(self.field_name)
        field = model_field.formfield()
        field.required = True

        self.fields[self.field_name] = field

    def get_user(self, email=None):
        if connection.vendor == "postgresql":
            query = {self.field_name: email}
        else:
            query = {"%s__iexact" % self.field_name: email}
        return get_user_model()._default_manager.get(**query)

    def clean(self) -> dict[str, Any]:
        cleaned_data = super().clean()
        try:
            self.user = self.get_user(cleaned_data[self.field_name])
        except get_user_model().DoesNotExist:
            raise ValidationError(self.error_messages["email_mismatch"])
        return cleaned_data

    def get_mail_context(self, user):
        return {
            "user": user,
        }

    def send_mail(self):
        if self.user:
            to_email = self.cleaned_data[self.field_name]
            self.email_device = EmailDevice(user=self.user, email=to_email)
            return self.email_device.generate_challenge(
                extra_context=self.get_mail_context(self.user))


class VerifyOtpForm(forms.Form):
    session: OTPSession | None

    auth_id = forms.CharField(
        label=_('auth id'),
        max_length=256,
        required=True,
        widget=widgets.HiddenInput(),
    )

    otp = forms.CharField(
        label=_('認証コード'),
        min_length=6,
        max_length=6,
        required=True,
        validators=[
            validators.RegexValidator(r'^[\d]+$'),
        ]
    )

    def __init__(self, *args, **kwargs) -> None:
        self.session = kwargs.pop('session', None)
        super().__init__(*args, **kwargs)

    def clean(self) -> dict[str, Any]:
        session = self.session

        cleaned_data = super().clean()
        auth_id = cleaned_data.get("auth_id")
        otp = cleaned_data.get("otp")
        if not auth_id or not otp:
            raise ValidationError('最初からやり直してください')

        if not session or not isinstance(session, OTPSession):
            raise ValidationError('最初からやり直してください')

        try:
            user = get_user_model().objects.get(pk=session.user_pk)
            email_device: EmailDevice = EmailDevice.objects.get(
                pk=session.device_pk,
                user=user)
        except ObjectDoesNotExist:
            raise ValidationError('最初からやり直してください')
        else:
            verify_is_allowed, reason = email_device.verify_is_allowed()
            if not verify_is_allowed:
                logger.warn(reason)
                raise ValidationError('最初からやり直してください')
            calced_auth_id = UserEmailOTPSigner().signature(email_device)
            if not constant_time_compare(calced_auth_id, auth_id):
                raise ValidationError('最初からやり直してください')

        if not email_device.verify_token(otp):
            raise ValidationError('正しい認証コードを入力してください')

        self.user = user
        return cleaned_data
