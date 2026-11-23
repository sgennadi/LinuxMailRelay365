# RC11 — conditional sender/domain routing: what-if planner

RC11 introduces an **offline, read-only route condition model** inside the
existing discovery-first Windows wizard. It is hidden until the current Linux
MTA/SMTP inspection completes and collapsed by default.

## Supported proposal conditions

| Condition | Example | Meaning |
| --- | --- | --- |
| Exact envelope sender | user@example.org | Only the exact SMTP MAIL FROM mailbox |
| Envelope sender domain | example.org | Only the exact domain after the sender's @ |
| Recipient domain | external.example.org | Only the exact domain after the recipient's @ |

Each candidate specifies an **outbound** relay FQDN/IPv4, TCP port 1–65535,
STARTTLS/implicit TLS/plaintext, and proposed SMTP AUTH/no AUTH. No password
is requested or stored in this planner. The configured **inbound Linux SMTP
port is not changed or inferred from the outbound port**.

Rules can be added, edited, reordered for display, removed, and tested using
user-supplied sample sender and recipient addresses. Editing a rule is local,
can be cancelled, and does not alter the original until Save is chosen.
Rules are also displayed as native, clickable WinForms condition → outbound
SMTP diagrams. Clicking either node opens that rule's in-memory editor;
potential overlaps are highlighted, but no precedence is inferred. All
diagram elements remain programmatic, with responsive narrow/200%-DPI layouts.
Simulation results are invalidated if the rule plan or sample sender/recipient
changes, avoiding stale results from another hypothetical message. Simulations report
all matching candidates. Zero matches means no proposal; one means only
a *hypothetical* match; multiple means overlapping conditions requiring
review. There is **no simulated or implied Postfix precedence**.

## Existing configuration remains protected

The wizard reports *declarations only* for detected Postfix
\`sender_dependent_relayhost_maps\` and \`transport_maps\`, without reading
their content or SMTP credentials. Exim/Sendmail routers and ACLs are NOT
modeled. All rules live only in Windows process memory and are cleared
when the SSH server identity changes; they are not written to a local
plan file, uploaded, or applied to Linux.

This distinction is essential: Postfix envelope sender routing and
recipient/domain transport maps use different lookup order and mechanisms.
Adding one table of generic rules is not proof of actual behavior, and
the tool intentionally **does not expose an Apply button** for conditional
routes yet.

## Next implementation work

Before a real Apply is permitted:

1. inspect the *effective* Postfix routing mechanisms without disclosing
   password maps or mailbox contents;
2. model sender/recipient policy precedence and any sender-dependent SASL
   state exactly and identify local/virtual delivery conflicts;
3. Preview an exact, diffable, root-owned *manager-specific* map; refuse
   overwriting non-owned transport, sender or TLS maps;
4. review remote relay DNS, TLS certificate, provider sender authorization
   and credentials for each destination separately;
5. make an exact SHA-bound backup, write atomically, validate with
   \`postfix check\`, reload, and verify; restore on failure;
6. repeat this work with native Exim/Sendmail semantics separately, not by
   copying Postfix settings.

**This is unsigned development code, not an external delivery test or
permission to change production routes.** No SMTP connection, tenant object
or mail message is changed by this RC11 planner.
