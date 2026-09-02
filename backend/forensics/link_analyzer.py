# Link Analyzer Module

import re
import urllib.parse
from backend.threat_intelligence import query_virustotal_domain

URL_REGEX = re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+', re.IGNORECASE)

def extract_and_analyze_links(body_text: str, body_html: str = "") -> list:
    """
    Extracts URLs from email body and queries real threat intelligence where configured.
    Does not produce fabricated scores.
    """
    combined_body = f"{body_text or ''}\n{body_html or ''}"
    raw_urls = URL_REGEX.findall(combined_body)
    unique_urls = list(dict.fromkeys(raw_urls))

    analyzed_links = []
    for url in unique_urls:
        try:
            parsed = urllib.parse.urlparse(url)
            domain = parsed.netloc.split(":")[0].lower()
            
            vt_res = query_virustotal_domain(domain)
            status = "SUSPICIOUS" if (vt_res.get("positives") or 0) > 0 else "UNKNOWN"

            analyzed_links.append({
                "url": url,
                "defanged_url": url.replace("http://", "hxxp://").replace("https://", "hxxps://"),
                "domain": domain,
                "status": status,
                "virustotal_positives": vt_res.get("positives"),
                "virustotal_total": vt_res.get("total"),
                "virustotal_status": vt_res.get("status")
            })
        except Exception:
            analyzed_links.append({
                "url": url,
                "defanged_url": url,
                "domain": "",
                "status": "UNKNOWN",
                "virustotal_positives": None,
                "virustotal_total": None,
                "virustotal_status": "error"
            })

    return analyzed_links
