# Policies

Policies are rules checked against each project's latest release. Their violations show on the dashboard (portfolio, project page, **Policies** page) and through the API.

## Kinds

| Kind | Violated when | `value` |
|---|---|---|
| `license` | A component declares this license | SPDX license ID, case-insensitive, e.g. `GPL-3.0-only` |
| `severity` | An unsuppressed finding has at least this severity | `critical`, `high`, `medium` or `low` |
| `kev` | An unsuppressed finding is in the KEV catalog | unused |
| `epss` | An unsuppressed finding has an [EPSS](vulnerabilities.md#likely-to-be-exploited-epss) score at least this high | A probability, `0.5`, or a percentage, `50%`; stored as a probability |

License policies match the IDs declared in the SBOM, including inside license expressions: a policy on `GPL-3.0-only` matches a component declaring `GPL-3.0-only OR MIT`. Components whose SBOM entry declares no license never match.

## Managing policies

Policies are managed with the admin token:

```sh
# Create
curl -X POST "$TOCSIN_URL/api/policies" -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" -d '{"name": "No AGPL", "kind": "license", "value": "AGPL-3.0-only"}'
curl -X POST "$TOCSIN_URL/api/policies" -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" -d '{"name": "No critical", "kind": "severity", "value": "critical"}'
curl -X POST "$TOCSIN_URL/api/policies" -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" -d '{"name": "Likely exploited", "kind": "epss", "value": "50%"}'

# List
curl "$TOCSIN_URL/api/policies" -H "Authorization: Bearer $ADMIN_TOKEN"

# Delete
curl -X DELETE "$TOCSIN_URL/api/policies/2" -H "Authorization: Bearer $ADMIN_TOKEN"
```

## Violations

```sh
curl "$TOCSIN_URL/api/projects/my-service/violations" -H "Authorization: Bearer $TOKEN"
```

```json
[{"project": "my-service", "policy_id": 1, "policy": "No AGPL", "kind": "license",
  "subject": "pkg:npm/some-lib@2.1.0", "detail": "AGPL-3.0-only"}]
```

`subject` is the component (license policies) or the vulnerability (other kinds). Like the findings, violations can gate a CI pipeline: fail the build when the list is not empty.
