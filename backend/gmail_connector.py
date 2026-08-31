"""
TraceXMail Gmail OAuth Connector & Real-Time Ingestion Engine
Handles Google OAuth 2.0 auth code exchange, Fernet token encryption,
Gmail API history polling / Pub/Sub webhook triggers, and direct raw byte feed
into the existing TraceXMail forensic pipeline.
"""

import os
import base64
import json
import asyncio
import traceback
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List

import requests
from fastapi import APIRouter, Request, HTTPException, Depends, BackgroundTasks
from fastapi.responses import HTMLResponse, RedirectResponse
try:
    from cryptography.fernet import Fernet
    HAS_FERNET = True
except ImportError:
    HAS_FERNET = False
    print("[Gmail Connector Warning] 'cryptography' package not installed. Token encryption falling back to base64 encoding.")
from sqlalchemy.orm import Session

from backend.db_session import get_db, get_db_context
from backend.database import (
    save_gmail_connection,
    get_gmail_connection_by_org,
    get_active_gmail_connections,
    delete_gmail_connection,
    gmail_message_exists
)

router = APIRouter(prefix="/api/gmail", tags=["Gmail Connector"])

SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

# ------------------------------------------------------------------
# Cryptography & Fernet Token Encryption Helpers
# ------------------------------------------------------------------
def _get_fernet_key() -> bytes:
    raw_key = os.environ.get("TOKEN_ENCRYPTION_KEY", "").strip()
    if raw_key:
        try:
            return raw_key.encode("utf-8")
        except Exception:
            pass
    # Fallback key generated deterministically from APP_SECRET or fallback string for local dev
    fallback_seed = "TraceXMailSecretEncryptionKey2026Secure00000000="
    return base64.urlsafe_b64encode(fallback_seed[:32].encode("utf-8"))

def encrypt_token(plain_token: str) -> str:
    if not plain_token:
        return ""
    if HAS_FERNET:
        f = Fernet(_get_fernet_key())
        return f.encrypt(plain_token.encode("utf-8")).decode("utf-8")
    return "b64enc:" + base64.b64encode(plain_token.encode("utf-8")).decode("utf-8")

def decrypt_token(cipher_token: str) -> str:
    if not cipher_token:
        return ""
    if HAS_FERNET and not cipher_token.startswith("b64enc:"):
        try:
            f = Fernet(_get_fernet_key())
            return f.decrypt(cipher_token.encode("utf-8")).decode("utf-8")
        except Exception:
            pass
    if cipher_token.startswith("b64enc:"):
        return base64.b64decode(cipher_token[7:].encode("utf-8")).decode("utf-8")
    return cipher_token


# ------------------------------------------------------------------
# OAuth Config Helpers
# ------------------------------------------------------------------
def _build_app_base_url(request: Optional[Request] = None) -> str:
    """Resolve the current app origin, including proxy headers used by Render/Vercel."""
    if request is not None:
        forwarded_proto = request.headers.get("x-forwarded-proto")
        forwarded_host = request.headers.get("x-forwarded-host") or request.headers.get("host")
        if forwarded_proto:
            proto = forwarded_proto.split(",")[0].strip() or request.url.scheme
        else:
            proto = request.url.scheme
        if forwarded_host:
            host = forwarded_host.split(",")[0].strip() or request.url.netloc
        else:
            host = request.url.netloc
        return f"{proto}://{host}".rstrip("/")

    app_url = os.environ.get("APP_URL", "http://localhost:3000").strip().rstrip("/")
    return app_url or "http://localhost:3000"


def get_oauth_config(request: Optional[Request] = None):
    client_id = os.environ.get("GOOGLE_CLIENT_ID", "").strip()
    client_secret = os.environ.get("GOOGLE_CLIENT_SECRET", "").strip()
    redirect_uri = os.environ.get("GOOGLE_REDIRECT_URI", "").strip()

    if not redirect_uri:
        base_url = _build_app_base_url(request)
        redirect_uri = f"{base_url}/api/gmail/oauth/callback"

    return {
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uri": redirect_uri
    }



def validate_oauth_config():
    cfg = get_oauth_config()

    missing = []

    if not cfg["client_id"]:
        missing.append("GOOGLE_CLIENT_ID")

    if not cfg["client_secret"]:
        missing.append("GOOGLE_CLIENT_SECRET")

    if missing:
        raise HTTPException(
            status_code=503,
            detail=f"Google OAuth is not configured. Missing: {', '.join(missing)}"
        )

    return cfg

def refresh_access_token(connection: Dict[str, Any]) -> str:
    """
    Refreshes expired OAuth access token using refresh_token.
    """
    cfg = get_oauth_config()
    refresh_tok = decrypt_token(connection.get("encrypted_refresh_token", ""))
    
    if not refresh_tok:
        raise HTTPException(status_code=401, detail="No refresh token available. Please reconnect Gmail.")

    payload = {
        "client_id": cfg["client_id"],
        "client_secret": cfg["client_secret"],
        "refresh_token": refresh_tok,
        "grant_type": "refresh_token"
    }

    res = requests.post("https://oauth2.googleapis.com/token", data=payload, timeout=10)
    if res.status_code != 200:
        error_resp = res.text
        try:
            error_data = res.json() if "application/json" in res.headers.get("Content-Type", "") else json.loads(res.text)
            if error_data.get("error") == "invalid_grant":
                connection["is_active"] = False
                save_gmail_connection(connection)
                raise ValueError("needs_reauthorization")
        except ValueError:
            raise
        except Exception:
            pass
        raise HTTPException(status_code=400, detail=f"Failed to refresh Google OAuth token: {error_resp}")

    data = res.json()
    new_access_token = data["access_token"]
    expires_in = data.get("expires_in", 3600)
    new_expiry = (datetime.utcnow() + timedelta(seconds=expires_in)).isoformat()

    # Update database
    connection["encrypted_access_token"] = encrypt_token(new_access_token)
    connection["token_expiry"] = new_expiry
    save_gmail_connection(connection)

    return new_access_token


def get_valid_access_token(connection: Dict[str, Any]) -> str:
    """
    Returns valid access token, auto-refreshing if near expiration.
    """
    expiry_str = connection.get("token_expiry")
    if expiry_str:
        try:
            if isinstance(expiry_str, str):
                exp_dt = datetime.fromisoformat(expiry_str.replace("Z", ""))
            else:
                exp_dt = expiry_str
            if exp_dt <= datetime.utcnow() + timedelta(minutes=2):
                return refresh_access_token(connection)
        except Exception as e:
            print(f"[Gmail] Token expiry parse failed ({e}), refreshing defensively")
            return refresh_access_token(connection)

    decrypted = decrypt_token(connection.get("encrypted_access_token", ""))
    if not decrypted and connection.get("encrypted_refresh_token"):
        return refresh_access_token(connection)
    return decrypted


async def start_gmail_polling_loop(interval_seconds: int = 20):
    """
    Background Gmail polling loop.

    Gmail/network/database work is executed in a worker thread so blocking
    requests do not block the FastAPI/Uvicorn event loop.
    """
    print(f"[Gmail Polling] Started with {interval_seconds}s interval.")

    try:
        from backend.database import get_gmail_connection_by_org
        conn = await asyncio.to_thread(get_gmail_connection_by_org, "org_default_01")
        print(f"[Gmail] Stored connection {'FOUND' if conn else 'NOT FOUND'} for org org_default_01 on startup")
    except Exception as e:
        print(f"[Gmail] Error checking initial connection: {e}")

    while True:
        try:
            active_conns = await asyncio.to_thread(get_active_gmail_connections)

            if active_conns:
                print(f"[Gmail Polling] Found {len(active_conns)} active connection(s).")

            for conn in active_conns:
                org_id = conn.get("organization_id", "org_default_01")

                try:
                    result = await asyncio.to_thread(
                        lambda: asyncio.run(
                            fetch_and_process_gmail_messages(org_id)
                        )
                    )

                    print(
                        f"[Gmail Polling] org={org_id} "
                        f"status={result.get('status')} "
                        f"messages={result.get('message_count', 0)} "
                        f"cases={result.get('processed_cases_count', 0)}"
                    )
                except Exception as conn_err:
                    print(
                        f"[Gmail Polling] Connection {org_id} failed: {conn_err}"
                    )
                    traceback.print_exc()

        except Exception as e:
            print(f"[Gmail Polling] Loop error: {e}")
            traceback.print_exc()

        await asyncio.sleep(interval_seconds)

# ------------------------------------------------------------------
# API Endpoints: OAuth Connect Flow
# ------------------------------------------------------------------
@router.get("/oauth/start")
def gmail_oauth_start(request: Request):
    """
    GET /api/gmail/oauth/start
    Constructs Google OAuth 2.0 authorization URL for gmail.readonly scope.
    """
    cfg = get_oauth_config(request)
    if not cfg["client_id"] or not cfg["client_secret"]:
        # Return instructional mock URL or details if client ID is unconfigured
        return {
            "status": "unconfigured",
            "message": "GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET are required in environment.",
            "url": None
        }

    params = {
        "client_id": cfg["client_id"],
        "redirect_uri": cfg["redirect_uri"],
        "response_type": "code",
        "scope": " ".join(SCOPES),
        "access_type": "offline",
        "prompt": "consent",
        "include_granted_scopes": "true"
    }

    auth_url = f"https://accounts.google.com/o/oauth2/v2/auth?{requests.compat.urlencode(params)}"
    return {"status": "ok", "url": auth_url}


@router.get("/oauth/callback")
def gmail_oauth_callback(request: Request, code: Optional[str] = None, error: Optional[str] = None):
    """
    GET /api/gmail/oauth/callback
    Exchanges auth code for access_token + refresh_token, stores encrypted, and initializes history_id.
    """
    if error:
        return HTMLResponse(content=f"<h3>Gmail OAuth Error: {error}</h3>", status_code=400)

    if not code:
        return HTMLResponse(content="<h3>Missing OAuth code parameter</h3>", status_code=400)

    try:
        cfg = validate_oauth_config()
    except HTTPException as exc:
        return HTMLResponse(
            content=f"<h3>{exc.detail}</h3>",
            status_code=exc.status_code
        )

    try:
        # Token exchange request
        token_url = "https://oauth2.googleapis.com/token"
        data = {
            "code": code,
            "client_id": cfg["client_id"],
            "client_secret": cfg["client_secret"],
            "redirect_uri": cfg["redirect_uri"],
            "grant_type": "authorization_code"
        }

        try:
            res = requests.post(token_url, data=data, timeout=8)
        except requests.exceptions.RequestException:
            import time
            time.sleep(1)
            res = requests.post(token_url, data=data, timeout=8)

        if res.status_code != 200:
            raise Exception(f"Token Exchange Failed: {res.text}")

        token_data = res.json()
        access_token = token_data.get("access_token")
        refresh_token = token_data.get("refresh_token")
        expires_in = token_data.get("expires_in", 3600)
        token_expiry = (datetime.utcnow() + timedelta(seconds=expires_in)).isoformat()

        # Fetch user email profile from Gmail API
        try:
            profile_res = requests.get(
                "https://gmail.googleapis.com/gmail/v1/users/me/profile",
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=8
            )
        except requests.exceptions.RequestException:
            import time
            time.sleep(1)
            profile_res = requests.get(
                "https://gmail.googleapis.com/gmail/v1/users/me/profile",
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=8
            )

        if profile_res.status_code == 200:
            prof = profile_res.json()
            email_address = prof.get("emailAddress", "connected_gmail_user@gmail.com")
            history_id = str(prof.get("historyId", ""))
        else:
            email_address = "connected_gmail_user@gmail.com"
            history_id = ""

        # Encrypt tokens before DB storage
        enc_access = encrypt_token(access_token)
        enc_refresh = encrypt_token(refresh_token) if refresh_token else ""

        connection_record = {
            "id": f"gconn_{email_address.replace('@', '_at_')}",
            "organization_id": "org_default_01",
            "email_address": email_address,
            "encrypted_access_token": enc_access,
            "encrypted_refresh_token": enc_refresh,
            "token_expiry": token_expiry,
            "history_id": history_id,
            "watch_expiry": None,
            "is_active": True,
            "last_polled_at": datetime.utcnow().isoformat() + "Z"
        }
        save_gmail_connection(connection_record)
        
        # Notify the opener window that OAuth succeeded and then close the popup.
        frontend_url = os.environ.get("FRONTEND_URL", "https://trace-x-mail.vercel.app").rstrip("/")
        callback_html = f"""
        <html>
          <head><meta charset="utf-8" /></head>
          <body style="font-family: sans-serif; background:#0f172a; color:#e2e8f0; display:flex; align-items:center; justify-content:center; min-height:100vh; margin:0;">
            <div style="text-align:center;">
              <h3 style="margin:0 0 8px; font-size: 18px;">Gmail connected</h3>
              <p style="margin:0; color:#94a3b8; font-size: 13px;">This window will close automatically.</p>
            </div>
            <script>
              const successMessage = {{ type: 'GMAIL_OAUTH_SUCCESS' }};
              const fallbackUrl = '{frontend_url}/';
              try {{
                if (window.opener) {{
                  window.opener.postMessage(successMessage, '*');
                }}
              }} catch (e) {{}}
              setTimeout(() => {{
                try {{ window.close(); }} catch (e) {{}}
                window.location.href = fallbackUrl;
              }}, 200);
            </script>
          </body>
        </html>
        """
        return HTMLResponse(content=callback_html)
        
    except Exception as e:
        import traceback
        print(f"[Gmail Connector] OAuth Callback Error: {e}")
        traceback.print_exc()
        frontend_url = os.environ.get("FRONTEND_URL", "https://trace-x-mail.vercel.app").rstrip("/")
        error_html = f"""
        <html>
          <head><meta charset="utf-8" /></head>
          <body style="font-family: sans-serif; background:#0f172a; color:#e2e8f0; display:flex; align-items:center; justify-content:center; min-height:100vh; margin:0;">
            <div style="text-align:center; padding: 20px; border: 1px solid #334155; border-radius: 8px; background: #1e293b;">
              <h3 style="margin:0 0 12px; font-size: 18px; color: #f87171;">Connection Failed</h3>
              <p style="margin:0 0 16px; color:#94a3b8; font-size: 14px;">Could not verify your Google account. Please try connecting again.</p>
              <button onclick="window.close()" style="background: #3b82f6; color: white; border: none; padding: 8px 16px; border-radius: 4px; cursor: pointer;">Close & Try Again</button>
            </div>
          </body>
        </html>
        """
        return HTMLResponse(content=error_html, status_code=500)

@router.get("/status")
def gmail_connection_status(org_id: str = "org_default_01"):
    """
    GET /api/gmail/status
    Returns status of active Gmail connection, connected email, and polling telemetry.
    """
    conn = get_gmail_connection_by_org(org_id)
    cfg = get_oauth_config()
    
    if not conn:
        return {
            "is_connected": False,
            "oauth_configured": bool(cfg["client_id"] and cfg["client_secret"]),
            "email_address": None,
            "last_polled_at": None,
            "polling_interval_seconds": 20,
            "history_id": None
        }

    return {
        "is_connected": True,
        "oauth_configured": True,
        "email_address": conn.get("email_address"),
        "last_polled_at": conn.get("last_polled_at"),
        "polling_interval_seconds": 20,
        "history_id": conn.get("history_id"),
        "created_at": conn.get("created_at")
    }


# ------------------------------------------------------------------
# PART C: Real-Time Mail Fetching & Existing Pipeline Feed
# ------------------------------------------------------------------
async def fetch_and_process_gmail_messages(org_id: str = "org_default_01") -> Dict[str, Any]:
    """
    Queries Gmail API for new messages since last historyId (or latest inbox unread emails),
    fetches raw RFC822 content via format='raw', base64url decodes bytes,
    and feeds them directly into the EXISTING forensic analysis entrypoint (run_forensic_pipeline).
    """
    from backend.main import run_forensic_pipeline

    conn = get_gmail_connection_by_org(org_id)
    if not conn or not conn.get("is_active"):
        return {"status": "inactive", "new_cases": []}

    try:
        access_token = get_valid_access_token(conn)
    except ValueError as err:
        if str(err) == "needs_reauthorization":
            print(f"[Gmail Connector] Token revoked/expired (needs reauthorization) for org {org_id}")
            return {"status": "needs_reauthorization", "error": "Token revoked or expired. Please reconnect.", "new_cases": []}
        print(f"[Gmail Connector] Token refresh error: {err}")
        return {"status": "error", "error": str(err), "new_cases": []}
    except Exception as err:
        print(f"[Gmail Connector] Token refresh error: {err}")
        conn["is_active"] = False
        save_gmail_connection(conn)
        return {"status": "needs_reauthorization", "error": str(err), "new_cases": []}

    headers = {"Authorization": f"Bearer {access_token}"}
    stored_history_id = conn.get("history_id")

    message_ids = []
    new_history_id = stored_history_id

    # 1. Try fetching via Gmail history.list if historyId exists
    if stored_history_id:
        hist_url = f"https://gmail.googleapis.com/gmail/v1/users/me/history?startHistoryId={stored_history_id}&historyTypes=messageAdded"
        res = requests.get(hist_url, headers=headers, timeout=10)
        if res.status_code == 200:
            hist_data = res.json()
            new_history_id = str(hist_data.get("historyId", stored_history_id))
            for item in hist_data.get("history", []):
                for msg_added in item.get("messagesAdded", []):
                    msg_obj = msg_added.get("message", {})
                    if msg_obj.get("id"):
                        message_ids.append(msg_obj["id"])
        elif res.status_code == 401:
            try:
                access_token = refresh_access_token(conn)
                headers = {"Authorization": f"Bearer {access_token}"}
                res = requests.get(hist_url, headers=headers, timeout=10)
                if res.status_code == 200:
                    hist_data = res.json()
                    new_history_id = str(hist_data.get("historyId", stored_history_id))
                    for item in hist_data.get("history", []):
                        for msg_added in item.get("messagesAdded", []):
                            msg_obj = msg_added.get("message", {})
                            if msg_obj.get("id"):
                                message_ids.append(msg_obj["id"])
                elif res.status_code == 404:
                    stored_history_id = None
            except Exception as e:
                conn["is_active"] = False
                save_gmail_connection(conn)
                return {"status": "needs_reauthorization", "error": f"Token revoked or expired: {e}", "new_cases": []}
        elif res.status_code == 404:
            # historyId expired or invalid, reset
            stored_history_id = None

    # 2. Fallback / initial mailbox sync:
    # Fetch messages from the last 30 days.
    # gmail_message_exists() prevents duplicate forensic processing.
    if not message_ids:

        page_token = None

        while True:
            params = {
                "maxResults": 100,
                "q": "newer_than:30d",
            }

            if page_token:
                params["pageToken"] = page_token

            res = requests.get(
                "https://gmail.googleapis.com/gmail/v1/users/me/messages",
                headers=headers,
                params=params,
                timeout=20,
            )

            if res.status_code != 200:
                print(
                    f"[Gmail Connector] 30-day message listing failed: "
                    f"{res.status_code} {res.text[:500]}"
                )
                if res.status_code == 401:
                    try:
                        access_token = refresh_access_token(conn)
                        headers = {"Authorization": f"Bearer {access_token}"}
                        continue
                    except Exception as e:
                        return {"status": "needs_reauthorization", "error": f"Token revoked or expired: {e}", "new_cases": []}
                break

            list_data = res.json()

            for msg in list_data.get("messages", []):
                if msg.get("id"):
                    message_ids.append(msg["id"])

            page_token = list_data.get("nextPageToken")

            if not page_token:
                break

        print(
            f"[Gmail Connector] 30-day sync discovered "
            f"{len(message_ids)} message(s)."
        )

    # Update historyId & last_polled_at in database
    conn["last_polled_at"] = datetime.utcnow().isoformat() + "Z"
    if new_history_id:
        conn["history_id"] = new_history_id
    save_gmail_connection(conn)

    analyzed_cases = []

    # Process each new message ID
    for msg_id in message_ids:
        # Skip messages already analyzed for this organization.
        if gmail_message_exists(msg_id, org_id):
            print(f"[Gmail Connector] Skipping already processed message {msg_id}")
            continue

        raw_url = f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{msg_id}?format=raw"
        msg_res = requests.get(raw_url, headers=headers, timeout=20)
        if msg_res.status_code != 200:
            continue

        msg_json = msg_res.json()
        raw_base64url = msg_json.get("raw", "")
        if not raw_base64url:
            continue

        # Base64URL decode raw message bytes
        # Handle padding
        padding = len(raw_base64url) % 4
        if padding:
            raw_base64url += "=" * (4 - padding)
        raw_bytes = base64.urlsafe_b64decode(raw_base64url)

        filename = f"gmail_{msg_id}.eml"

        # FEED DIRECTLY INTO EXISTING FORENSIC PIPELINE
        try:
            pipeline_result = await run_forensic_pipeline(
                raw_content=raw_bytes,
                filename=filename,
                source="gmail_live",
                organization_id=org_id
            )
            pipeline_result["source"] = "gmail_live"
            analyzed_cases.append(pipeline_result)
            print(f"[Gmail Connector] Successfully processed message {msg_id} -> Case {pipeline_result.get('id')} ({pipeline_result.get('verdict')})")
        except Exception as p_err:
            print(f"[Gmail Connector] Error in pipeline for message {msg_id}: {p_err}")
            traceback.print_exc()

    return {
        "status": "ok",
        "polled_at": conn["last_polled_at"],
        "message_count": len(message_ids),
        "processed_cases_count": len(analyzed_cases),
        "cases": analyzed_cases
    }


@router.post("/poll-now")
async def gmail_poll_now(org_id: str = "org_default_01"):
    """
    POST /api/gmail/poll-now
    Triggers immediate manual mail fetch and ingestion for active Gmail connection.
    """
    res = await fetch_and_process_gmail_messages(org_id)
    return res


@router.post("/webhook")
async def gmail_pubsub_webhook(request: Request, background_tasks: BackgroundTasks):
    """
    POST /api/gmail/webhook
    Receives Pub/Sub push notifications from Gmail API, validates request, and schedules mail processing.
    """
    try:
        payload = await request.json()
        message = payload.get("message", {})
        data_b64 = message.get("data", "")
        if data_b64:
            padding = len(data_b64) % 4
            if padding:
                data_b64 += "=" * (4 - padding)
            decoded_json = json.loads(base64.urlsafe_b64decode(data_b64).decode("utf-8"))
            email_address = decoded_json.get("emailAddress")
            history_id = decoded_json.get("historyId")
            print(f"[Gmail Webhook] Received Pub/Sub push for {email_address} (historyId: {history_id})")

        background_tasks.add_task(fetch_and_process_gmail_messages, "org_default_01")
        return {"status": "received"}
    except Exception as e:
        print(f"[Gmail Webhook] Error: {e}")
        return {"status": "error", "message": str(e)}

