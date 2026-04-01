# Security Policy

## Supported Versions

Versions currently being supported with security updates.

| Version | Supported          | EOL           |
| ------- | ------------------ | ------------- |
| v1.2.x  | :x:                | Jun 1st 2022  |
| v2.x    | :white_check_mark: | TBD           |
| v3.x    | :white_check_mark: | Not defined   |

## Reporting a Vulnerability

To report a security issue, please follow [this link](https://github.com/corazawaf/coraza/security/advisories/new) and add a description of the issue, the steps you took to create the issue, affected versions, and, if known, mitigations for the issue.

Our vulnerability management team will respond within 3 working days of your report. If the issue is confirmed as a vulnerability, we will open a Security Advisory. This project follows a 90 day disclosure timeline.

We follow the [Guide to coordinated vulnerability disclosure for open source software projects](https://github.com/ossf/oss-vulnerability-guide) where possible.

## Reporting Policy

The open source ecosystem is increasingly affected by AI-generated security reports that sound professional but lack technical substance or real exploitability. To protect maintainer time and ensure the quality of our security process, we apply the following policy to all incoming vulnerability reports.

### Core Principles

1. **Verification over Verbiage**: Regardless of length or presentation, a report without a script or a clear, reproducible execution path demonstrating the bug is considered invalid and will be closed without further review.

2. **Anti-LLM Filtering**: Reports that show signs of AI-generated content (e.g. ChatGPT-style phrasing, purely theoretical claims without working evidence, generic vulnerability descriptions not tied to specific code) will be rejected as spam.

3. **Impact over Theory**: A valid report must demonstrate how the bug concretely affects the confidentiality, integrity, or availability of the system in a real-world scenario. Speculative or hypothetical impact descriptions are not sufficient.

4. **No "Paper CVEs"**: We actively discourage and will contest CVE attributions for reports found to be AI-generated spam or non-exploitable hallucinations. CVEs should reflect real, demonstrated vulnerabilities.

### Required Report Contents

A valid security report **must** include:

- A clear description of the vulnerability and the affected component.
- A **working Proof of Concept (PoC)**: a self-contained script, test case, or step-by-step sequence that reliably reproduces the issue. Reports without a working PoC will be rejected.
- The affected version(s).
- A description of the real-world impact, including what an attacker can achieve by exploiting the vulnerability.

Reports that do not satisfy these requirements will be closed as invalid without further discussion.

## :trophy: Hall of Fame :trophy:

1. No records
