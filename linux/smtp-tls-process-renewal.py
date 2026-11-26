"""Process a renewed certificate through existing staging and activation adapters."""
def process(cert,chain,key,domain,ca,stage,current,validate,activate):
    candidate=stage(cert,chain,key,domain,ca)
    validate(candidate)
    if current()==candidate:
        return {"status":"unchanged","generation":candidate,"exchange_acceptance":"unverified"}
    result=activate(candidate)
    return {"status":result,"generation":candidate,"exchange_acceptance":"unverified"}
