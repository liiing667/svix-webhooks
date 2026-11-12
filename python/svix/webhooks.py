import typing as t
from datetime import datetime

from standardwebhooks.exceptions import WebhookVerificationError
from standardwebhooks.webhooks import Webhook as StdWh

_SVIX_HEADERS = ("svix-id", "svix-signature", "svix-timestamp")
_UNBRANDED_HEADERS = ("webhook-id", "webhook-signature", "webhook-timestamp")


class Webhook:
    _inner: StdWh

    def __init__(self, whsecret: t.Union[str, bytes]):
        self._inner = StdWh(whsecret)

    def verify(self, data: t.Union[bytes, str], headers: t.Dict[str, str]) -> None:
        headers = {k.lower(): v for k, v in headers.items()}

        has_svix_headers = any(key in headers for key in _SVIX_HEADERS)
        has_unbranded_headers = any(key in headers for key in _UNBRANDED_HEADERS)
        if has_svix_headers and has_unbranded_headers:
            raise WebhookVerificationError(
                "mixed svix-* and webhook-* headers are not allowed; "
                "use one complete set of signature headers"
            )

        headers["webhook-id"] = headers.get("svix-id", headers.get("webhook-id", ""))
        headers["webhook-signature"] = headers.get(
            "svix-signature", headers.get("webhook-signature", "")
        )
        headers["webhook-timestamp"] = headers.get(
            "svix-timestamp", headers.get("webhook-timestamp", "")
        )

        self._inner.verify(data, headers, json_parse=False)

    def sign(self, msg_id: str, timestamp: datetime, data: str) -> str:
        return self._inner.sign(msg_id, timestamp, data)


__all__ = ["Webhook", "WebhookVerificationError"]
