"""Build a conservative managed TLS detach candidate."""
import hashlib
import re
VALUE=b"/etc/postfix/lmr365-smtp-tls/active/client-chain.pem"

def build(original,previous):
    if any(b"\x00" in x or b"\r" in x for x in (original,previous)):
        raise ValueError("unsupported configuration encoding")
    def locate(data):
        lines=data.splitlines(True)
        matches=[i for i,line in enumerate(lines) if re.match(rb"^smtp_tls_chain_files[ \t]*=",line)]
        if len(matches)>1:
            raise ValueError("duplicate TLS setting")
        if matches:
            i=matches[0]
            if i+1<len(lines) and lines[i+1].startswith((b" ",b"\t")):
                raise ValueError("continued TLS setting")
        return lines,matches
    lines,matches=locate(original)
    old,prior=locate(previous)
    if not matches or lines[matches[0]].split(b"=",1)[1].strip()!=VALUE:
        raise ValueError("managed TLS setting not found")
    if prior and old[prior[0]].split(b"=",1)[1].strip():
        raise ValueError("previous TLS identity requires manual review")
    i=matches[0]
    lines[i:i+1]=[old[prior[0]].rstrip(b"\n")+b"\n"] if prior else []
    return b"".join(lines)

def preview(original,previous):
    candidate=build(original,previous)
    return dict(original_sha256=hashlib.sha256(original).hexdigest(),
                backup_sha256=hashlib.sha256(previous).hexdigest(),
                candidate_sha256=hashlib.sha256(candidate).hexdigest(),
                apply_supported=False)
