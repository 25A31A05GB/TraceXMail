# Header Parser Module

import email
from email.header import decode_header

def _decode_str(header_val: str) -> str:
    if not header_val:
        return ""
    decoded_chunks = decode_header(header_val)
    parts = []
    for chunk, encoding in decoded_chunks:
        if isinstance(chunk, bytes):
            parts.append(chunk.decode(encoding or "utf-8", errors="ignore"))
        else:
            parts.append(str(chunk))
    return "".join(parts)

def extract_email_data(raw_email: str) -> dict:
    """
    Parses RFC822 raw email string and extracts structured headers and body content.
    """
    if not raw_email or not isinstance(raw_email, str):
        return {
            "from": "",
            "from_domain": "",
            "to": "",
            "subject": "",
            "date": "",
            "message_id": "",
            "received_headers": [],
            "body_text": "",
            "body_html": "",
            "attachments": [],
            "status": "error"
        }

    msg = email.message_from_string(raw_email)

    from_hdr = _decode_str(msg.get("From", ""))
    to_hdr = _decode_str(msg.get("To", ""))
    subject_hdr = _decode_str(msg.get("Subject", ""))
    date_hdr = _decode_str(msg.get("Date", ""))
    msg_id = _decode_str(msg.get("Message-ID", ""))

    # Extract from domain
    from_domain = ""
    if "@" in from_hdr:
        from_domain = from_hdr.split("@")[-1].replace(">", "").strip()

    received_headers = msg.get_all("Received") or []

    body_text = ""
    body_html = ""
    attachments = []

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            disp = str(part.get("Content-Disposition", ""))
            if "attachment" in disp:
                filename = part.get_filename() or "attachment"
                attachments.append({"filename": filename, "content_type": content_type})
            elif content_type == "text/plain" and not body_text:
                payload = part.get_payload(decode=True)
                if payload:
                    body_text = payload.decode(part.get_content_charset() or "utf-8", errors="ignore")
            elif content_type == "text/html" and not body_html:
                payload = part.get_payload(decode=True)
                if payload:
                    body_html = payload.decode(part.get_content_charset() or "utf-8", errors="ignore")
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            body_text = payload.decode(msg.get_content_charset() or "utf-8", errors="ignore")

    return {
        "from": from_hdr,
        "from_domain": from_domain,
        "to": to_hdr,
        "subject": subject_hdr,
        "date": date_hdr,
        "message_id": msg_id,
        "received_headers": received_headers,
        "body_text": body_text,
        "body_html": body_html,
        "attachments": attachments,
        "status": "ok"
    }
