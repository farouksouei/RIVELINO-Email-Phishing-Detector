import pytest
from fastapi.testclient import TestClient

PHISHING_EMAIL = """\
From: "PayPal Security" <security@paypa1-alerts.tk>
Reply-To: collect@evil-domain.ml
To: victim@example.com
Subject: Re: Urgent: Your account has been suspended!
Date: Thu, 29 May 2026 10:00:00 +0000
Received: from mail.evil.xyz (1.2.3.4) by mx.example.com; Thu, 29 May 2026 10:00:00 +0000
Authentication-Results: mx.example.com; spf=fail; dkim=none; dmarc=fail
Content-Type: text/html; charset=utf-8

<html><body>
<p>Dear Customer,</p>
<p>Your PayPal account has been SUSPENDED immediately due to suspicious activity!</p>
<p>You must verify your account NOW or it will be permanently closed within 24 hours!</p>
<p><a href="http://1.2.3.4/login?verify=paypal">Click here to verify your account</a></p>
<form action="http://evil.tk/steal">
  <input type="password" placeholder="Enter your password">
</form>
<p>Failure to act will result in legal action and police involvement.</p>
</body></html>
"""

LEGITIMATE_EMAIL = """\
From: "GitHub" <noreply@github.com>
To: developer@example.com
Subject: [GitHub] A new public key was added to your account
Date: Thu, 29 May 2026 09:00:00 +0000
Received: from smtp.github.com (192.30.252.1) by mx.example.com; Thu, 29 May 2026 09:00:01 +0000
Authentication-Results: mx.example.com; spf=pass; dkim=pass; dmarc=pass
Content-Type: text/plain; charset=utf-8

Hi developer,

A new public SSH key was added to your GitHub account.

If this was you, no action is required.

If you did not add this key, please visit https://github.com/settings/keys
to review and remove it immediately.

Thanks,
The GitHub Team
"""


@pytest.fixture
def phishing_email() -> str:
    return PHISHING_EMAIL


@pytest.fixture
def legitimate_email() -> str:
    return LEGITIMATE_EMAIL


@pytest.fixture
def test_client():
    from unittest.mock import MagicMock
    from app.main import app
    from app.schemas.response import AnalysisResponse

    mock_model = MagicMock()
    mock_model.analyze.return_value = AnalysisResponse(
        verdict="phishing",
        confidence=0.95,
        risk_level="critical",
        summary="Test phishing email (mocked).",
        processing_time_ms=5.0,
    )

    with TestClient(app) as client:
        app.state.model = mock_model
        yield client
