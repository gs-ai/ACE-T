from __future__ import annotations

import datetime as dt
from typing import Optional

ISO_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"


def utcnow() -> dt.datetime:
    return dt.datetime.utcnow().replace(tzinfo=dt.timezone.utc)


def format_ts(ts: Optional[dt.datetime] = None) -> str:
    return (ts or utcnow()).strftime(ISO_FORMAT)


def parse_ts(value: str) -> dt.datetime:
    return dt.datetime.strptime(value, ISO_FORMAT).replace(tzinfo=dt.timezone.utc)


__all__ = ["utcnow", "format_ts", "parse_ts"]
