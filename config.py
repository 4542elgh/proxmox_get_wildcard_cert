import os
from dotenv import load_dotenv

load_dotenv()

if os.getenv("REMOTE_URL") is None or os.getenv("REMOTE_URL") == "" or os.getenv("REMOTE_CERT_LOCATION") is None or os.getenv("LOCAL_CERT_LOCATION") is None:
    raise ValueError("Environment variables REMOTE_URL, REMOTE_CERT_LOCATION, and LOCAL_CERT_LOCATION must be set.")

REMOTE_URL:str = os.getenv("REMOTE_URL", "")
REMOTE_CERT_LOCATION:str = os.getenv("REMOTE_CERT_LOCATION", "")
LOCAL_CERT_LOCATION:str = os.getenv("LOCAL_CERT_LOCATION", "")

# Optional and can be None
NOTIFICATION_SERVICE:str | None = os.getenv("NOTIFICATION_SERVICE", None)
WEBHOOK_URL:str | None = os.getenv("WEBHOOK_URL", None)
APPRISE_TAG:str | None = os.getenv("APPRISE_TAG", None)
