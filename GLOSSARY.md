# Tocsin

Tocsin tracks the known vulnerabilities in what each project runs in production, and warns when one is exploited or likely to be.

## Language

### What a project runs

**Release**:
One successfully deployed production version of a project, described by its uploaded SBOM.
_Avoid_: build, deployment

**Latest release**:
The project's declared production release: the last accepted upload, a rollback re-upload included. A project has at most one.
_Avoid_: current version, highest version

### Vulnerabilities

**Advisory**:
One record of a flaw, from one source (GitHub, RustSec, Debian…), with its own ID.
_Avoid_: vulnerability, entry

**Vulnerability**:
One flaw: the advisories sharing a CVE, named by that CVE, or a single advisory without CVE, named by its ID. It keeps its identity when its name changes, for example when an advisory gains a CVE.
_Avoid_: flaw, issue, CVE (as a generic word)

**Matched**:
Said of a project when a component of its latest release is listed by an advisory of the vulnerability, whatever its analysis says.
_Avoid_: affected (for the raw match)

**Finding**:
A vulnerability matched in one project's latest release.
_Avoid_: issue, vulnerability (for the per-project record)

**Affected**:
Said of a project that has an unsuppressed finding for the vulnerability.
_Avoid_: impacted, vulnerable

### Auditing

**Analysis**:
The decision recorded for a finding: a VEX state, an optional justification and a rationale. Its rationale survives evidence changes; any suppression requires acceptance of the current evidence.
_Avoid_: audit (as a noun), triage, assessment

**Auditing**:
The activity of recording analyses.
_Avoid_: triaging, reviewing

**Suppressed**:
Said of a finding whose analysis accepts its current matched versioned purls and advisory applicability as not affected, false positive or resolved.
_Avoid_: ignored, hidden, muted

### Exploitation signals

**KEV**:
Said of a vulnerability with a CVE in CISA's Known Exploited Vulnerabilities catalog: attackers are known to exploit it.
_Avoid_: exploited (alone), critical

**EPSS score**:
FIRST's daily probability that a CVE sees exploitation activity in the next 30 days; a vulnerability takes the highest score of its CVEs.
_Avoid_: risk score, exploitability

### Rules

**Policy**:
A criterion a project's latest release must not meet (a license, a minimum severity, KEV, an EPSS score), set from the dashboard or the API.
_Avoid_: rule, alert rule

**Violation**:
A component or unsuppressed finding that meets a policy's criterion.
_Avoid_: breach, policy alert

**Alert rule**:
A criterion that warrants an immediate message when an unsuppressed finding meets it (KEV by default), set in the configuration.
_Avoid_: policy, trigger

**Alert**:
The message sent for a finding that meets an alert rule, once per rule and actionable episode; retries may deliver duplicates.
_Avoid_: notification, violation

**Evidence**:
The exact matched versioned package identifiers and material advisory applicability supporting a finding.
_Avoid_: vulnerability name, severity

**Pending revalidation**:
An analysis whose rationale is retained but whose suppression is not accepted for the current evidence.
_Avoid_: suppressed, dismissed

**Actionable episode**:
An uninterrupted period in which a finding is present and unsuppressed, beginning after absence or suppression. Threshold oscillations and component changes alone do not create another episode.
_Avoid_: alert cycle

**Matching coverage**:
The extent of successful vulnerability evaluation among all supplied components, including identifier gaps and evaluation provenance. It is not an assurance of safety.
_Avoid_: processing status, safe
