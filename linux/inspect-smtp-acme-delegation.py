"""Read-only ACME challenge delegation inspection."""
import re

def inspect(name, query, discover):
    current="_acme-challenge."+name.lower().rstrip(".")
    chain=[current]
    for _ in range(8):
        targets=query(current,"CNAME")
        if not targets:
            zone=discover(current.split(".",1)[1] if current.startswith("_acme-challenge.") else current)
            return dict(challenge=chain[0],target=current,chain=chain,
                        zone_hint=zone,automatic_issuance_verified=False,
                        delegated=len(chain)>1)
        if len(targets)!=1:
            raise ValueError("ambiguous challenge delegation")
        target=targets[0].lower().rstrip(".")
        if len(target)>253 or not all(re.fullmatch(r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?",x) for x in target.split(".")):
            raise ValueError("invalid challenge target")
        if target in chain:
            raise ValueError("challenge delegation loop")
        chain.append(target)
        current=target
    raise ValueError("challenge delegation depth exceeded")
