"""Detach orchestration. Caller holds both ACME and deployment locks."""
def detach(plan, read, previous, planner, deploy, backup, replace, restore,
           assert_inactive, assert_alternative, check, reload, journal):
    if planner.preview(read(),previous)!=plan:
        raise ValueError("detach plan changed")
    def preflight():
        assert_inactive()
        assert_alternative()
    return deploy.deploy(plan["original_sha256"],plan["candidate_sha256"],
        read,lambda original:planner.build(original,previous),backup,replace,
        restore,preflight,lambda:None,check,reload,journal)
