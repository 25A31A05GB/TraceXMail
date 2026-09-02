# Evidence Vault for immutable email hash storage
import hashlib

def store_evidence(raw_bytes: bytes) -> str:
    sha256_hash = hashlib.sha256(raw_bytes).hexdigest()
    return sha256_hash
