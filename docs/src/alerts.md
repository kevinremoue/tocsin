# Alerts

Tocsin posts a message when a project is affected by a vulnerability that matches an alert rule. Each (project, vulnerability, rule) is notified **only once**: a vulnerability that stays in your stack does not ping you again on every release.

## Rules

| Rule | Setting | Default |
|---|---|---|
| The finding is in the KEV catalog | `TOCSIN_ALERT_KEV` | on |
| The finding has at least a given severity | `TOCSIN_ALERT_MIN_SEVERITY` (`critical`, `high`, `medium`, `low`) | off |
| The finding's EPSS score is at least a threshold | `TOCSIN_ALERT_MIN_EPSS` (`0.5` or `50%`) | off |

EPSS scores change every day. A finding whose score rises above the threshold alerts on the day it crosses it, and only then: a score that later drops and rises again does not alert twice. For scale: in any 30-day window, exploitation activity is observed for only 2–3% of all CVEs, so a score of 10% is already well above average, and 50% is a strong signal.

Suppressed findings (audited as not affected, false positive or resolved) never alert.

## When alerts are sent

- **After an SBOM push**, for the pushed project: a new release introduces a vulnerability.
- **After the KEV sync**, for all projects: CISA added a CVE that one of your releases contains.
- **After the refresh job**, for all projects: an advisory was published for a component you already ship.
- **After the EPSS sync**, for all projects: a finding's EPSS score reached the threshold.

## Google Chat

1. In Google Chat, open the space, then **Apps & integrations → Webhooks → Add webhook**.
2. Copy the webhook URL, and set it as `TOCSIN_GOOGLE_CHAT_WEBHOOK`.
3. Set `TOCSIN_PUBLIC_URL` to the dashboard's URL so that messages link to the project and vulnerability pages.

One message is sent per project and evaluation, listing the new vulnerabilities:

```
🔔 my-service is affected by 1 new vulnerability:
• CVE-2021-44228 · Critical · actively exploited (KEV) · EPSS 94% · Remote code injection in Log4j
   in pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1
```

## Delivery

- An alert is recorded only once its message was delivered. If the webhook fails, the alert is retried at the next evaluation.
- Without a notification channel, nothing is evaluated or recorded. When you configure one later, the first evaluation sends what is pending.
- Evaluations take a database lock, so several instances (serverless scaling) never send the same alert twice.

The **Alerts** page of the dashboard lists the alerts sent, and the current rules. The notifier is pluggable: more channels (Slack, email, generic webhooks) are on the [roadmap](roadmap.md).
