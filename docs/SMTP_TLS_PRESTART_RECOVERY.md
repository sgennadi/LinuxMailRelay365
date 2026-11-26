# Pre-start recovery
Enable the pre-start recovery unit only after managed TLS deployment.
It restores an interrupted generation without issuing a reload, because
Postfix is about to start. The unit must be required by postfix.service.
Do not manually start this unit while Postfix is running; use the normal
recovery service instead. Verify distribution-specific service names and
ordering before installation. No automatic installation is provided.
