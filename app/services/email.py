from abc import ABC, abstractmethod
from typing import Any
from app.core.config import settings

class EmailProvider(ABC):
    """
    Abstract base class for email providers.
    """
    @abstractmethod
    async def send_email(self, to: str, subject: str, body: str) -> bool:
        """
        Send an email to the specified recipient.
        """
        pass

    async def send_verification_email(self, to: str, token: str) -> bool:
        """
        Send a verification email with a link.
        """
        # In a real app, you'd use a template
        link = f"{settings.ISSUER_URL}/verify-email?token={token}"
        subject = f"Verify your email for {settings.APP_NAME}"
        body = f"Please click the link to verify your email: {link}"
        return await self.send_email(to, subject, body)

    async def send_password_reset_email(self, to: str, token: str) -> bool:
        """
        Send a password reset email with a link.
        """
        link = f"{settings.ISSUER_URL}/reset-password?token={token}"
        subject = f"Reset your password for {settings.APP_NAME}"
        body = f"Please click the link to reset your password: {link}\nIf you did not request this, please ignore this email."
        return await self.send_email(to, subject, body)


class ConsoleEmailProvider(EmailProvider):
    """
    Email provider that prints emails to the console.
    Useful for development and testing.
    """
    async def send_email(self, to: str, subject: str, body: str) -> bool:
        print(f"--- EMAIL START ---")
        print(f"To: {to}")
        print(f"From: {settings.FROM_EMAIL}")
        print(f"Subject: {subject}")
        print(f"Body:\n{body}")
        print(f"--- EMAIL END ---")
        return True


def get_email_provider() -> EmailProvider:
    """
    Factory function to get the configured email provider.
    """
    if settings.EMAIL_PROVIDER.lower() == "console":
        return ConsoleEmailProvider()
    # Future providers can be added here
    # elif settings.EMAIL_PROVIDER.lower() == "sendgrid":
    #     return SendGridEmailProvider()
    else:
        # Default to console or raise error
        return ConsoleEmailProvider()
