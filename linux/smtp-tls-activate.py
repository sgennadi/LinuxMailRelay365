"""Internal renewal activation orchestration. Requires validated candidate and managed Postfix configuration."""
import json
from pathlib import Path

def activate(root,candidate,generation,transaction,check,reload,validate_tls):
    root=Path(root)
    with transaction.deployment_lock(root):
        journal=root/"deployment.json"
        if journal.exists():
            state=json.loads(journal.read_text())
            if state.get("phase") not in ("verified","rolled_back"):
                raise ValueError("unfinished transaction; recovery required")
        previous=generation.current(root)
        if previous is None:
            raise ValueError("initial deployment requires separate configuration transaction")
        generation.validate(root,candidate)
        validate_tls(candidate)
        check()
        if previous==candidate:
            return "unchanged"
        transaction.record(root,previous,candidate,"prepared")
        try:
            generation.switch(root,candidate,previous)
            transaction.record(root,previous,candidate,"switched")
            check()
            reload()
            transaction.record(root,previous,candidate,"verified")
            return "reloaded"
        except Exception:
            transaction.record(root,previous,candidate,"rollback_required")
            active=generation.current(root)
            if active==candidate:
                generation.switch(root,previous,candidate)
            elif active!=previous:
                raise ValueError("unexpected active generation; manual recovery required")
            check()
            reload()
            transaction.record(root,previous,candidate,"rolled_back")
            raise

def recover(root,generation,transaction,check,reload,before_recover=lambda: None):
    """Conservatively restore previous generation after an interrupted renewal."""
    root=Path(root)
    with transaction.deployment_lock(root):
        before_recover()
        journal=root/"deployment.json"
        if not journal.exists():
            return "no_transaction"
        state=json.loads(journal.read_text())
        if state.get("version")!=1:
            raise ValueError("unknown journal version")
        phase=state["phase"]
        previous=state["previous"]
        candidate=state["candidate"]
        if phase not in ("prepared","switched","rollback_required","verified","rolled_back"):
            raise ValueError("unknown journal phase")
        generation.validate(root,previous)
        generation.validate(root,candidate)
        active=generation.current(root)
        if phase in ("verified","rolled_back"):
            if active!=(candidate if phase=="verified" else previous):
                raise ValueError("terminal journal disagrees with active generation")
            return "unchanged"
        if active not in (previous,candidate):
            raise ValueError("unexpected generation; manual recovery required")
        transaction.record(root,previous,candidate,"rollback_required")
        if active==candidate:
            generation.switch(root,previous,candidate)
        check()
        reload()
        transaction.record(root,previous,candidate,"rolled_back")
        return "restored"
