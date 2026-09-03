#!/usr/bin/env python3
"""
TraceXMail Forensic Dataset Builder & Authenticator
Downloads and cleans authentic SpamAssassin ham to replace corrupted entries,
merging with validated Nazario Phishing and Curated Threat corpora.
"""

import json
import os
import re
import urllib.request
import tarfile
import io
import email
import email.policy
from collections import Counter

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_PATH = os.path.join(BASE_DIR, 'data/datasets/real_corpus.json')

def fetch_authentic_spamassassin_ham(target_count=400):
    url = 'https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham.tar.bz2'
    print(f'[Dataset Builder] Fetching authentic Apache SpamAssassin Easy Ham from {url}...')
    req = urllib.request.Request(url, headers={'User-Agent': 'TraceXMail-Dataset-Builder/1.0'})
    with urllib.request.urlopen(req, timeout=30) as resp:
        tar_bytes = resp.read()

    print(f'[Dataset Builder] Downloaded {len(tar_bytes)} bytes. Parsing MIME messages...')
    tar = tarfile.open(fileobj=io.BytesIO(tar_bytes), mode='r:bz2')
    
    ham_records = []
    seen_bodies = set()

    for member in tar.getmembers():
        if not member.isfile() or member.name.endswith('cmds'):
            continue
        f = tar.extractfile(member)
        if not f:
            continue
        try:
            raw = f.read()
            msg = email.message_from_bytes(raw, policy=email.policy.default)
            subject = str(msg.get('Subject', '') or 'No Subject').replace('\n', ' ').strip()
            from_hdr = str(msg.get('From', '') or '').replace('\n', ' ').strip()
            
            body = ''
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == 'text/plain':
                        body += part.get_payload(decode=True).decode('utf-8', errors='ignore')
            else:
                pl = msg.get_payload(decode=True)
                if pl:
                    body = pl.decode('utf-8', errors='ignore')
                else:
                    body = str(msg.get_payload())
            
            body = body.replace('\r', '').strip()
            # Clean snippet for deduplication
            snip = body[:200]
            if len(body) > 40 and snip not in seen_bodies:
                seen_bodies.add(snip)
                domain = 'mail.org'
                m = re.search(r'@([a-zA-Z0-9.-]+)', from_hdr)
                if m:
                    domain = m.group(1).lower()
                
                ham_records.append({
                    'id': f'sa_easyham_{len(ham_records)}',
                    'subject': subject,
                    'text': body[:3000],
                    'from': from_hdr,
                    'fromDomain': domain,
                    'label': 'Legitimate',
                    'source': 'Apache SpamAssassin Public Ham Benchmark (20030228_easy_ham)'
                })
                if len(ham_records) >= target_count:
                    break
        except Exception:
            continue

    print(f'[Dataset Builder] Successfully extracted {len(ham_records)} authentic Ham records.')
    return ham_records

def build_clean_corpus():
    with open(DATASET_PATH, 'r', encoding='utf-8') as f:
        existing = json.load(f)

    # Filter out corrupted sa_ham_* records (which were actually Nazario phishing)
    clean_threats = [r for r in existing if not r.get('id', '').startswith('sa_ham_')]
    print(f'[Dataset Builder] Retained {len(clean_threats)} verified threat records.')

    authentic_ham = fetch_authentic_spamassassin_ham(target_count=410)

    # Combine
    combined = authentic_ham + clean_threats

    # Deduplicate by subject + first 100 chars of body
    unique = []
    seen = set()
    for r in combined:
        key = (r['subject'].lower().strip(), r['text'][:120].lower().strip())
        if key not in seen:
            seen.add(key)
            unique.append(r)

    print(f'[Dataset Builder] Final clean deduplicated corpus size: {len(unique)}')
    dist = Counter(r['label'] for r in unique)
    print(f'[Dataset Builder] Class distribution: {dict(dist)}')

    with open(DATASET_PATH, 'w', encoding='utf-8') as f:
        json.dump(unique, f, indent=2)
    print(f'[Dataset Builder] Saved clean corpus to {DATASET_PATH}')

if __name__ == '__main__':
    build_clean_corpus()
