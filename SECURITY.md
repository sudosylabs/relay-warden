# Security policy

## Supported versions

Relay Warden is pre-release. Security fixes are developed on `main`; there
are no maintained stable release branches or guaranteed backports yet.
If you use a development build, record its commit and keep it up to date.
Do not assume older snapshots receive security updates.

## Reporting a vulnerability

Do not open a public issue or pull request containing an exploit, admin
token, private key or sensitive deployment information.

Email [support@sudosy.fr](mailto:support@sudosy.fr) with the subject
**Relay Warden security report**. Share the report privately; do not attach
live credentials or data belonging to other users.

You may also use **Security → Report a vulnerability** on GitHub if that
option is available. Its availability has not been verified for this
checkout; email is the documented reporting channel.

A useful private report includes:

- The affected version or commit and relevant operating system.
- The security impact and prerequisites, including whether admin access is
  required.
- Reproduction steps or a minimal proof of concept using test identities and
  synthetic data.
- Any suggested mitigation, without access credentials for a live service.

Test only systems you own or have permission to assess. Avoid disrupting
other users, spending a provider's quota or collecting their traffic.

## Handling reports

Maintainers will assess the report privately, ask for clarification when
needed, and coordinate a fix and disclosure with the reporter. Please avoid
publishing exploit details while that coordination is ongoing. This project
does not currently offer a response-time SLA or a bug bounty.

## Scope and deployment responsibilities

Issues such as approval bypass, unauthorized administration, credential
exposure, quota bypass and remotely triggered resource exhaustion are
security-relevant. Report uncertainty privately rather than posting a
possible exploit publicly.

Keep administration on loopback or behind a private access mechanism, use
a strong admin token, protect the state directory, and expose the relay over
HTTPS. See [installation](docs/INSTALL.md) and [operations](docs/OPERATIONS.md).
Relay accounting is not an exact cloud-billing cap, and traffic from other
services needs separate monitoring. Passing tests is not a security audit.
