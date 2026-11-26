"""Pure initial TLS candidate builder."""
import re
import hashlib
VALUE=b"/etc/postfix/lmr365-smtp-tls/active/client-chain.pem"
def build(original):
    if b"\x00" in original or b"\r" in original:
        raise ValueError("unsupported configuration")
    lines=original.splitlines(True)
    matches=[i for i,line in enumerate(lines) if re.match(rb"^smtp_tls_chain_files[ \t]*=",line)]
    if len(matches)>1:
        raise ValueError("duplicate TLS setting")
    setting=b"smtp_tls_chain_files = "+VALUE+b"\n"
    if matches:
        i=matches[0]
        if i+1<len(lines) and lines[i+1].startswith((b" ",b"\t")):
            raise ValueError("continued TLS setting")
        value=lines[i].split(b"=",1)[1].strip()
        if value not in (b"",VALUE):
            raise ValueError("existing TLS identity")
        if value==VALUE:
            return original
        lines[i]=setting
        return b"".join(lines)
    return original+(b"\n" if original and not original.endswith(b"\n") else b"")+setting
def preview(original):
    candidate=build(original)
    return {"original_sha256":hashlib.sha256(original).hexdigest(),
            "candidate_sha256":hashlib.sha256(candidate).hexdigest(),
            "changed":candidate!=original}
