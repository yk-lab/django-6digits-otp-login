from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from django.contrib.auth.base_user import AbstractBaseUser
from django.core import signing
from django_otp.plugins.otp_email.models import EmailDevice


@dataclass
class OTPSession:
    device_pk: type[EmailDevice.pk]
    user_pk: type[AbstractBaseUser.pk]
    auth_id: str | None = None


class UserEmailOTPSigner(signing.Signer):
    @staticmethod
    def to_timestamp(value: datetime | None):
        if value is None:
            return ""
        return signing.b62_encode(int(value.timestamp()))

    def signature(self, email_device: EmailDevice):
        return super().signature(value=self._make_hash_value(email_device))

    def _make_hash_value(self, email_device: EmailDevice):
        last_login = self.to_timestamp(email_device.user.last_login)
        user_pk = signing.b62_encode(email_device.user.pk)
        email_device_pk = signing.b62_encode(email_device.pk)
        return self.sep.join((user_pk, email_device_pk, last_login))
