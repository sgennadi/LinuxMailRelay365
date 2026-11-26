# Managed SMTP TLS recovery

Install the recovery unit and its Python modules together under the root-owned
/usr/local/libexec/linuxmailrelay365 directory. Enable recovery only after
initial managed Postfix TLS configuration. Recovery runs after Postfix starts,
not before it; this does not prevent a brief use of an interrupted generation
during boot. A failed recovery blocks dependent ACME renewal. The unit does
not install itself or enable automatic certificate activation.
