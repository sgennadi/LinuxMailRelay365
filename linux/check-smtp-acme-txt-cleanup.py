"""Compare DNS TXT snapshots without exposing challenge values."""
from collections import Counter

def compare(before,after):
    if before is None or after is None:
        return dict(status="unverified",txt_cleanup_verified=False)
    old=Counter(before)
    new=Counter(after)
    return dict(status="unchanged" if old==new else "changed",
                added_count=sum((new-old).values()),
                missing_count=sum((old-new).values()),
                txt_cleanup_verified=False,
                observed_snapshot_restored=old==new)

def inspect(query,name):
    try:
        return query("_acme-challenge."+name.rstrip("."))
    except (OSError,ValueError):
        return None
