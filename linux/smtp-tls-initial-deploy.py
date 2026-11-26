"""Internal initial deployment orchestration; system adapter supplied by caller."""
import hashlib

def digest(data):
    return hashlib.sha256(data).hexdigest()

def deploy(original_sha, candidate_sha, read, build, backup, replace,
           restore, preflight, validate, check, reload, journal):
    """Caller must hold deployment lock and prepare the active TLS generation."""
    preflight()
    validate()
    original=read()
    if digest(original)!=original_sha:
        raise ValueError("configuration changed since preview")
    candidate=build(original)
    if digest(candidate)!=candidate_sha:
        raise ValueError("candidate changed since preview")
    if candidate==original:
        check()
        return "unchanged"
    saved=backup()
    if read()!=original:
        raise ValueError("configuration changed during backup")
    journal("prepared",saved,original_sha,candidate_sha)
    try:
        replace(candidate,original_sha)
        journal("switched",saved,original_sha,candidate_sha)
        check()
        reload()
        journal("verified",saved,original_sha,candidate_sha)
        return "reloaded"
    except Exception:
        journal("rollback_required",saved,original_sha,candidate_sha)
        current=digest(read())
        if current==candidate_sha:
            restore(saved,candidate_sha)
        elif current!=original_sha:
            raise ValueError("unexpected configuration; manual recovery required")
        if digest(read())!=original_sha:
            raise ValueError("restore verification failed")
        reload()
        journal("rolled_back",saved,original_sha,candidate_sha)
        raise
