"""Validate staged TLS material separately and verify combined bundle."""
import re
import tempfile
from pathlib import Path

def validate(root,name,domain,ca,generation,checker):
    generation.validate(root,name)
    path=Path(root)/name
    full=(path/"fullchain.pem").read_bytes()
    key=(path/"key.pem").read_bytes()
    combined=(path/"client-chain.pem").read_bytes()
    if combined!=key.rstrip()+b"\n"+full:
        raise ValueError("combined TLS bundle mismatch")
    certs=re.findall(rb"-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----",full)
    if len(certs)<2 or re.sub(rb"-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----",b"",full).strip():
        raise ValueError("invalid certificate chain")
    with tempfile.TemporaryDirectory(dir=str(root),prefix=".validate-") as tmp:
        cert=Path(tmp)/"cert.pem"
        chain=Path(tmp)/"chain.pem"
        cert.write_bytes(certs[0]+b"\n")
        chain.write_bytes(b"\n".join(certs[1:])+b"\n")
        return checker.inspect(str(cert),str(chain),domain,ca,str(path/"key.pem"))
