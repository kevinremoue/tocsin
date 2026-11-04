# Pushing SBOMs from CI

Tocsin works best when every production release pushes its SBOM automatically. Push from the pipeline that **builds the release**, not from every commit: Tocsin matches against each project's latest release, which should be what runs in production.

## Generating a CycloneDX SBOM

Any tool that writes CycloneDX JSON works. A few common choices:

| Ecosystem | Tool |
|---|---|
| Any (filesystem or container image) | [Syft](https://github.com/anchore/syft): `syft <dir-or-image> -o cyclonedx-json=bom.json` |
| Many languages | [cdxgen](https://github.com/CycloneDX/cdxgen): `cdxgen -o bom.json` |
| Rust | [cargo-cyclonedx](https://github.com/CycloneDX/cyclonedx-rust-cargo) |
| Java | [CycloneDX Maven plugin](https://github.com/CycloneDX/cyclonedx-maven-plugin), [Gradle plugin](https://github.com/CycloneDX/cyclonedx-gradle-plugin) |
| JavaScript | [CycloneDX npm](https://github.com/CycloneDX/cyclonedx-node-npm) |

Tocsin matches components by their package URL (purl), which must include a version. Components without a purl are skipped, and so are purls without a version. All the tools above emit versioned purls.

Scanning the final container image captures OS packages too (Debian, Alpine…), which a language-level tool misses.

Component licenses declared in the SBOM are stored too, for [license policies](policies.md).

## Choosing the version

Tocsin stores one SBOM per (project, version). The version comes from:

1. the `?version=` query parameter, if present;
2. otherwise `metadata.component.version` in the SBOM.

The request fails with `400` if neither is set. Pushing the same version again replaces its SBOM, so re-running a release pipeline is safe.

## Large SBOMs: compress them

SBOMs compress very well (often 10 to 20 times). Send them gzip-compressed with `Content-Encoding: gzip`: uploads are faster, and large SBOMs stay under the request size limits of serverless platforms (32 MB on Cloud Run). The limit after decompression is 50 MB.

```sh
gzip -c bom.json | curl --fail-with-body -X POST "$TOCSIN_URL/api/sboms?version=1.4.2" \
  -H "Authorization: Bearer $TOCSIN_TOKEN" \
  -H "Content-Type: application/json" -H "Content-Encoding: gzip" \
  --data-binary @-
```

## The push response

```json
{"project": "my-service", "version": "1.4.2", "components": 187,
 "matching": "done", "findings": 12, "kev": 1, "alerted": 1}
```

- `matching` is `done` when the components were matched during the push, `deferred` when the vulnerability source was slow or unreachable (the next refresh job completes it), or `disabled` (`TOCSIN_MATCH_ON_PUSH=false`).
- `findings` and `kev` count the unsuppressed vulnerabilities of the project's latest release, and those in the KEV catalog.
- `alerted` is the number of vulnerabilities notified by this push.

## Failing a build on actively exploited vulnerabilities

The push response is enough to gate a release:

```sh
response=$(curl --fail-with-body -sS -X POST "$TOCSIN_URL/api/sboms?version=$VERSION" \
  -H "Authorization: Bearer $TOCSIN_TOKEN" -H "Content-Type: application/json" \
  --data-binary @bom.json)
echo "$response"
if [ "$(echo "$response" | jq .kev)" -gt 0 ]; then
  echo "This release contains actively exploited vulnerabilities:"
  curl -sS "$TOCSIN_URL/api/projects/my-service/findings" -H "Authorization: Bearer $TOCSIN_TOKEN" \
    | jq -r '.findings[] | select(.kev) | "\(.id) \(.summary) in \(.components | join(", "))"'
  exit 1
fi
```

The project token can read its own project's findings, so the same secret works for both calls. Findings audited as not affected, false positive or resolved are not counted. See [Vulnerabilities and auditing](vulnerabilities.md).

## GitHub Actions

Store the project token as a repository secret named `TOCSIN_TOKEN`, then add these steps to your release workflow:

```yaml
- name: Generate SBOM
  uses: anchore/sbom-action@v0
  with:
    format: cyclonedx-json
    output-file: bom.json
    upload-artifact: false

- name: Push SBOM to Tocsin
  run: |
    gzip -c bom.json | curl --fail-with-body -X POST "$TOCSIN_URL/api/sboms?version=${GITHUB_REF_NAME}" \
      -H "Authorization: Bearer ${{ secrets.TOCSIN_TOKEN }}" \
      -H "Content-Type: application/json" -H "Content-Encoding: gzip" \
      --data-binary @-
  env:
    TOCSIN_URL: https://tocsin.example.com
```

## GitLab CI

Store the project token as a masked CI/CD variable named `TOCSIN_TOKEN`:

```yaml
sbom:
  stage: deploy
  image: alpine:3
  rules:
    - if: $CI_COMMIT_TAG
  script:
    - apk add --no-cache curl
    - wget -qO- https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
    - syft . -o cyclonedx-json=bom.json
    - >
      gzip -c bom.json | curl --fail-with-body -X POST "$TOCSIN_URL/api/sboms?version=$CI_COMMIT_TAG"
      -H "Authorization: Bearer $TOCSIN_TOKEN"
      -H "Content-Type: application/json" -H "Content-Encoding: gzip"
      --data-binary @-
  variables:
    TOCSIN_URL: https://tocsin.example.com
```

## Troubleshooting

| Response | Cause |
|---|---|
| `401 invalid or missing bearer token` | The token is wrong, or the `Authorization: Bearer …` header is missing. |
| `400 release version missing` | Neither `?version=` nor `metadata.component.version` is set. |
| `400 unsupported bomFormat` / `invalid CycloneDX document` | The file is not CycloneDX JSON (SPDX and XML are not supported). |
| `413 Payload Too Large` | The SBOM is over 50 MB once decompressed, or over your platform's request limit: compress it. |
| `415 Unsupported Media Type` | The `Content-Type: application/json` header is missing. |
| `"matching": "deferred"` | OSV.dev was slow or unreachable. The release is stored; the next refresh job matches it. |
