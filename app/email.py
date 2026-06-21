"""Email sending — currently a mock/console implementation.

Why a "seam": real email needs an external provider (SMTP, SendGrid, etc.) with
credentials and network access, which is awkward to set up and to test. So all the
rest of the app calls ONE function — `send_email(...)` — and this module decides how
to deliver. Today it prints the message and stores it in an in-memory "outbox" so
tests (and you, in the terminal) can see exactly what would have been sent. Later,
swapping to real SMTP means editing only this file.
"""

from dataclasses import dataclass


@dataclass
class Email:
    to: str
    subject: str
    body: str


# A simple in-memory list of everything "sent". Tests inspect this; in real life it
# would be the provider's job. Cleared between tests via clear_outbox().
outbox: list[Email] = []


def clear_outbox() -> None:
    outbox.clear()


def send_email(to: str, subject: str, body: str) -> Email:
    """'Send' an email. For now: record it in the outbox and print it."""
    email = Email(to=to, subject=subject, body=body)
    outbox.append(email)
    # Visible feedback when running the server locally.
    print(f"\n--- EMAIL ---\nTo: {to}\nSubject: {subject}\n\n{body}\n-------------\n")
    return email


def send_bulk(recipients: list[str], subject: str, body: str) -> list[Email]:
    """Send the same message to many recipients (e.g. all admins of an org)."""
    return [send_email(to, subject, body) for to in recipients]
