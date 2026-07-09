## Security Policy

Phantom Grid is a **security-focused** project. We take vulnerabilities seriously and ask that you follow this policy when reporting issues.

---

## Supported Versions

This is a young project; generally, only the latest commit on the default branch is supported.

If we later add tagged releases, this section will be expanded to list which versions receive security fixes.

---

## Reporting a Vulnerability

**Please do not open public GitHub issues for security vulnerabilities.**

Instead:

1. Prepare a report that includes:
   - A clear description of the issue and its impact
   - Steps to reproduce (commands, configuration, environment)
   - Any proof-of-concept (PoC) code or captures
   - Your environment (OS, kernel version, Go version)
2. Send the report **privately** to the maintainer using the contact information in the repository description or project homepage.

If no explicit security email is listed, you can:

- Open a **minimal, generic issue** stating that you found a potential security problem and ask for a private contact channel (without sharing details publicly), or
- Use any contact information published by the author (e.g. on their GitHub profile or associated website).

---

## What to Expect

After you report a vulnerability:

1. We will acknowledge receipt of your report as soon as reasonably possible.
2. We will investigate the issue and may request more information.
3. We will work on a fix and may create a private branch or patch to validate the solution.
4. Once a fix is ready, we will:
   - Patch the issue
   - Optionally create a tagged release
   - Publish a brief note or changelog entry describing the impact (without exposing sensitive exploitation details prematurely)

When appropriate, we are happy to credit reporters in the release notes (unless you prefer to remain anonymous).

---

## Scope

In-scope examples:

- Bypassing SPA protection or critical ports protection
- Breaking isolation between real services and honeypot
- Remote code execution, privilege escalation, or data exfiltration bypassing the eBPF protections
- Logic flaws in eBPF handling leading to severe security gaps

Out-of-scope examples (for this project):

- Generic issues in unrelated dependencies (unless exploitable through Phantom Grid)
- Misconfiguration of the host OS or network outside of the documented setup

---

## Responsible Usage

Phantom Grid is intended for:

- Authorized security testing
- Research
- Defense / monitoring in environments you own or have explicit permission to test

You are responsible for complying with **all applicable laws and regulations** when using this software.


