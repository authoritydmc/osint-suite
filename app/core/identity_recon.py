"""Real identity lookups: Telegram (telethon, own account) + tool status.

Telegram shows name/photo like the apps do, but ONLY with your own
credentials: TELEGRAM_API_ID / TELEGRAM_API_HASH / TELEGRAM_SESSION
(StringSession). Without them this module reports unconfigured — nothing
is faked. Get API_ID/HASH at https://my.telegram.org, then generate a
session string once (see README) and store it as the env var.
"""
import os
from typing import Dict, Any


def telegram_status() -> Dict[str, Any]:
    cfg = bool(os.getenv("TELEGRAM_API_ID") and os.getenv("TELEGRAM_API_HASH")
               and os.getenv("TELEGRAM_SESSION"))
    return {"configured": cfg,
            "note": "Set TELEGRAM_API_ID/HASH/SESSION to enable live Telegram name/photo lookup" if not cfg else "ready"}


async def telegram_lookup_e164(e164: str) -> Dict[str, Any]:
    """Check if a +E.164 number is on Telegram; return name/username/photo flag.

    Uses ImportContacts + GetUsers (same primitives the apps use), then
    deletes the imported contact so nothing is left behind.
    """
    api_id = os.getenv("TELEGRAM_API_ID", "")
    api_hash = os.getenv("TELEGRAM_API_HASH", "")
    session = os.getenv("TELEGRAM_SESSION", "")
    if not (api_id and api_hash and session):
        return {"configured": False}
    try:
        from telethon import TelegramClient
        from telethon.sessions import StringSession
        from telethon.tl.functions.contacts import ImportContactsRequest, DeleteContactsRequest
        from telethon.tl.types import InputPhoneContact
    except Exception as e:
        return {"configured": True, "error": f"telethon missing: {e}"}
    try:
        async with TelegramClient(StringSession(session), int(api_id), api_hash) as client:
            res = await client(ImportContactsRequest(
                contacts=[InputPhoneContact(client_id=1, phone=e164,
                                            first_name="osint", last_name="lookup")]))
            users = [u for u in getattr(res, "users", []) if not getattr(u, "bot", False)]
            out: Dict[str, Any] = {"configured": True, "registered": bool(users)}
            if users:
                u = users[0]
                out.update({"first_name": getattr(u, "first_name", None),
                            "last_name": getattr(u, "last_name", None),
                            "username": getattr(u, "username", None),
                            "has_photo": bool(getattr(u, "photo", None)),
                            "user_id": getattr(u, "id", None)})
                try:
                    await client(DeleteContactsRequest(id=[u]))
                except Exception:
                    pass
            return out
    except Exception as e:
        return {"configured": True, "error": str(e)[:300]}
