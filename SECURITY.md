# Security

Version 1.0.1 is a reference implementation for trusted nodes. It is not a hardened
multi-tenant service, hardware attestation implementation, or production WAN gateway.

Do not include tickets, secret keys, private vendor code, runtime ledgers, or personal
data in public reports. Report reproducible defects without live credentials through
the repository's GitHub security reporting feature when available. Otherwise contact
the repository owner privately before publishing exploit details.

Use loopback by default. Use TLS at a trusted reverse proxy for remote connections.
Grant local-class tickets only to administrators. Vendor imports and gates execute
trusted code with the gateway user's OS permissions; they are not sandboxed.

Runtime state and ticket replay protection are volatile. Process restart invalidates
all previously issued tickets. A hash manifest is an integrity check against a local
baseline and does not authenticate a third-party publisher.
