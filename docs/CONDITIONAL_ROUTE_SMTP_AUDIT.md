# Independent SMTP diagnostics for conditional routes

Each conditional routing card now has an explicit DNS/TCP/TLS action.
It uses the card's own hostname, outbound port and TLS mode (no forced
port 2525 or provider). Password-mode cards have an additional one-shot
SMTP AUTH action with a masked, per-invocation credential dialog.

The existing custom SMTP probe runs from the discovered Linux host over
SSH stdin. STARTTLS and implicit TLS use normal certificate verification.
No credentials are sent in plaintext mode; no retry, file persistence,
mail submission, configuration write or sudo is introduced. Only validated
diagnostic statuses are retained, never username/password or server replies.

Results are bound to the SSH/discovery identity, configuration hash, ordered
rule-plan hash and exact rule. Changing the plan or discovered host invalidates
the displayed results. An accepted AUTH only describes that single submitted
credential at that destination; it does not prove Send As, recipient permission,
actual mail delivery or eligibility for Postfix Apply.

Multiple active authenticated transports, secret storage, OAuth token lifecycle
and provider-specific production activation are NOT implemented by this change.
The existing no-AUTH offline transaction path stays unchanged.
