"""Conservative TPM eligibility gate for SMTP certificate wizard."""
def evaluate(discovery,signature):
    reasons=[]
    if discovery.get("tpm2_verified") is not True:
        reasons.append("tpm2_not_verified")
    if discovery.get("tpm2_provider_loadable") is not True:
        reasons.append("provider_not_verified")
    if signature.get("signature_verified") is not True:
        reasons.append("signature_not_verified")
    reasons.append("postfix_provider_key_loading_not_qualified")
    reasons.append("hardware_key_acme_renewal_not_qualified")
    return dict(version=1,hardware_detected=discovery.get("tpm2_verified") is True,
                diagnostic_signature_passed=signature.get("signature_verified") is True,
                protection_available=False,standard_file_key_available=True,
                reasons=reasons)
