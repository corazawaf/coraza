# Security Policy

## Supported Versions

Versions currently being supported with security updates.

| Version | Supported          | EOL           |
| ------- | ------------------ | ------------- |
| v1.2.x  | :x:                | Jun 1st 2022  |
| v2.x    | :x:                | Jan 1st 2026  |
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

5. **Severity Reflects What the Attacker Controls, Not What the Bug Allows**: A CVSS score, and in particular Attack Complexity, must account for what has to be true for the bug to be reachable, not just that it exists. If exploitation depends on conditions outside the attacker's control — a specific behavior of the application behind Coraza (e.g. it echoes request content back into a response), a non-default configuration, or another vulnerability chained in — that is Attack Complexity: High, not Low, regardless of the impact once triggered. The same applies when the PoC only reproduces under one narrow, specific runtime environment (e.g. one exact patch version of an unrelated language runtime or framework, such as "Python 3.9.14 specifically") rather than against the affected code path in general: that is not evidence of a broadly exploitable bug, and the claimed affected version range is judged against how representative that environment actually is. We will re-score submissions during triage to reflect this, including downward, independent of the score the report proposes.

### CVSS scores are triaged, not accepted as submitted

Most reports we receive propose a High or Critical score by scoring only the impact once the bug fires, while leaving out what has to be true beforehand for an attacker to reach it. During triage we ask, explicitly:

- Does this fire from attacker-supplied input alone, against any deployment running the affected code? That is Attack Complexity: Low.
- Or does it additionally require something the attacker does not control — a specific way the protected application behaves, a specific configuration, privileged access, another bug chained in? That is Attack Complexity: High, and the report needs to name the precondition, not assume it away.
- Does it reproduce against the affected code path generally, or only through one specific, narrow environment — one exact pinned version of an unrelated runtime or third-party framework, rather than the range of versions the report claims as affected? A PoC that only works on one obscure combination is evidence about that combination, not about the code path in general, and is scored and scoped accordingly.

A report that does not address this distinction will have its score, and if needed its affected-version range, corrected during triage before an advisory is published. This does not make the report invalid on its own — a real, reproducible bug with an overstated score is still a real bug — but the published severity will reflect our assessment, not the submitted one.

### Required Report Contents

A valid security report **must** include:

- A clear description of the vulnerability and the affected component.
- A **working Proof of Concept (PoC)**: a self-contained script, test case, or step-by-step sequence that reliably reproduces the issue. Reports without a working PoC will be rejected.
- The affected version(s).
- A description of the real-world impact, including what an attacker can achieve by exploiting the vulnerability.
- Any preconditions the PoC depends on beyond attacker-supplied input (e.g. a specific behavior of the application behind Coraza, a non-default configuration). See "CVSS scores are triaged, not accepted as submitted" below — omitting this does not invalidate the report, but the published severity will be corrected during triage.

Reports missing a description, a working PoC, or affected versions will be closed as invalid without further discussion.

### AI Disclosure

When AI tools have materially contributed to the finding, the report **must** disclose:

1. **Which AI tools and models were used** (e.g., "GitHub Copilot", "Claude Opus 4.5", "ChatGPT-4o").
2. **What was generated or assisted** (e.g., the vulnerability hypothesis, the proof-of-concept script, the impact write-up).
3. **What review was performed** (e.g., reproduced by hand against a specific version/commit, traced the affected code path manually, verified the PoC independently of the tool).

Using AI, or disclosing that AI was used, does not by itself invalidate a report. Rejection is always tied to the "Core Principles" above: a missing reproducible PoC or unsupported/speculative claims. Omitting the disclosure above when AI materially contributed is itself treated as such an unsupported claim, and the report is closed as invalid on that basis.

## :trophy: Hall of Fame :trophy:

1. No records
