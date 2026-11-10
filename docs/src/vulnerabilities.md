# Vulnerabilities and auditing

## Findings

A **finding** is a vulnerability matched in a component of a project's **latest release**. Tocsin finds them by querying [OSV.dev](https://osv.dev) with each component's package URL. OSV aggregates many databases in one format: GitHub Advisories, the PyPI, npm, Go, RustSec and Maven ecosystems, Debian, Ubuntu, Alpine, and more.

An **advisory** is one source's record: for Log4Shell, `GHSA-jfh8-c2jp-5v3q` from GitHub and `CVE-2021-44228` from NVD. Tocsin groups advisories that share a CVE into **one vulnerability, named by its CVE**, and so one finding per project. An advisory without a CVE (some `RUSTSEC-…` or `GHSA-…` entries) is its own vulnerability, named by its ID. When an advisory later gains a CVE, its vulnerability is renamed and keeps its analyses and alerts (see [How it works](how-it-works.md#vulnerability-matching)).

A project is **affected** by a vulnerability when it has an unsuppressed finding for it; a project whose finding is suppressed is only **matched**. The vulnerability and KEV pages list both separately.

Findings are matched at two moments:

- **when an SBOM is pushed**, for the components that were not matched recently;
- **by the refresh job**, for every project's latest release, so that advisories published after a release are picked up (daily by default).

## Severity

Each finding has a severity: Critical, High, Medium, Low or Unknown.

1. When GitHub reviewed the advisory, its rating is used.
2. Otherwise Tocsin computes the CVSS v3 base score from the advisory's vector and rates it: 9.0 and above is Critical, 7.0 High, 4.0 Medium, above 0 Low.
3. Otherwise the severity is Unknown (for example advisories with only a CVSS v4 vector).

When advisories disagree, the finding takes the highest severity.

## Actively exploited: KEV

A finding whose CVE is in the [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) is marked **KEV**: attackers are known to exploit it. KEV findings come first in every list, count separately in the metrics, and trigger [alerts](alerts.md) by default.

Tocsin syncs the catalog every 6 hours by default. When CISA adds a CVE that affects one of your projects, the KEV sync alerts on it.

## Likely to be exploited: EPSS

The [Exploit Prediction Scoring System](https://www.first.org/epss) (EPSS), published by FIRST, gives every CVE a daily **probability of exploitation activity in the next 30 days**, from 0 to 1, and its percentile among all CVEs. KEV says a CVE *is* exploited; EPSS says how likely it is to be *soon*, which helps order the many findings that are not in KEV.

Each finding shows the highest score among its CVEs. Lists are ordered KEV first, then by EPSS score, then by severity. An EPSS score can also drive a [policy](policies.md) and an [alert](alerts.md) rule (`TOCSIN_ALERT_MIN_EPSS`).

The EPSS sync job (`tocsin epss-sync`, daily by default) downloads FIRST's daily file (about 3 MB, every scored CVE) and keeps only the scores of the CVEs Tocsin knows, a few hundred rows for a typical portfolio. FIRST asks tools keeping a copy of the scores to use this file rather than the API, which is meant for lookups. The download is conditional; when new advisories were stored since the last one, it runs in full so that their CVEs get a score. A CVE found after the day's sync gets its score at the next one.

Keep in mind what EPSS is not: it ignores your environment and the impact of an attack, and FIRST notes that direct evidence of exploitation (such as KEV) should take precedence over it. Scores also shift when FIRST releases a new model version; Tocsin records the version with each score.

EPSS scores are free to use; FIRST asks for attribution, which Tocsin gives in the dashboard footer and here: *EPSS scores by FIRST, <https://www.first.org/epss>*.

## Auditing

Not every finding is relevant: the vulnerable code may be unreachable, or the issue already mitigated. Record an **analysis** for a finding of a project.

**From the dashboard**, signed in with the admin token: click the Analysis cell of a finding (on the project page, a vulnerability page or a KEV entry), choose the state, a justification and a detail, then **Save**.

**From the API**, with the admin token:

```sh
curl -X PUT "$TOCSIN_URL/api/projects/my-service/analyses/CVE-2021-44228" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"state": "not_affected", "justification": "code_not_reachable", "detail": "JNDI lookups disabled"}'
```

The token must be the admin token. The vulnerability can be named by its CVE or by any of its advisory IDs.

States and justifications follow [CycloneDX VEX](https://cyclonedx.org/capabilities/vex/):

| State | Meaning | Suppressed |
|---|---|---|
| `in_triage` | Being investigated | No |
| `exploitable` | Confirmed to affect the project | No |
| `not_affected` | The project is not affected | **Yes** |
| `false_positive` | The match is wrong | **Yes** |
| `resolved` | Fixed or mitigated | **Yes** |

Justifications (optional, for `not_affected`): `code_not_present`, `code_not_reachable`, `requires_configuration`, `requires_dependency`, `requires_environment`, `protected_by_compiler`, `protected_at_runtime`, `protected_at_perimeter`, `protected_by_mitigating_control`.

**Suppressed** findings are hidden by default, are not counted in metrics, never alert, and do not violate policies. The dashboard can show them; the findings API returns them with `?suppressed=true`. Delete an analysis with `DELETE` on the same URL.

Analysis rationale survives new releases, but suppression applies only while the exact matched versioned purl set and material applicability remain accepted. Changed evidence requires revalidation.

## VEX export and import

`GET /api/projects/{name}/vex` returns the project's findings as a CycloneDX 1.6 VEX document, with their analyses. `POST /api/projects/{name}/vex` imports the analyses of a VEX document (from Tocsin, Dependency-Track or another tool), which is handy to share decisions between projects using the same component:

```sh
curl -s "$TOCSIN_URL/api/projects/shop/vex" -H "Authorization: Bearer $ADMIN_TOKEN" > vex.json
curl -X POST "$TOCSIN_URL/api/projects/blog/vex" -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" --data-binary @vex.json
# {"imported": 3, "skipped": []}
```

Vulnerabilities without an `analysis.state` are skipped and listed in `skipped`, with the reason.

## Evidence-bound suppression

Only administrators may record/delete analyses or import VEX; project tokens upload and read only. A suppression binds to the exact matched versioned purl set and material advisory applicability. Evidence changes or confirmed disappearance invalidate it, retaining the rationale pending revalidation. Existing analyses migrate pending revalidation. Cosmetic IDs, severity and EPSS changes alone do not invalidate acceptance.

The findings API exposes `analysis.pending_revalidation`. A retained suppressing state does not by itself mean the finding is suppressed: use `suppressed`. VEX exports include the `tocsin:evidence` property; importing suppressions requires that property and the exact current `affects` references, otherwise the import is rejected. Re-export and review the current evidence rather than editing identifiers to force an old decision through.

The dashboard shows **Pending revalidation** beside retained but ineffective suppressing states, plus matching coverage, license gaps, identifier timestamps, and the last complete historical evaluation during incomplete matching. Applicability arrays are normalized as sets and advisory `database_specific` presentation fields do not constitute material applicability.
