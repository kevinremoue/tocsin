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

Tocsin matches components by their package URL (purl). Components without a purl are skipped, so prefer tools that emit purls, which all of the above do.

Scanning the final container image captures OS packages too, which a language-level tool misses.

## Choosing the version

Tocsin stores one SBOM per (project, version). The version comes from:

1. the `?version=` query parameter, if present;
2. otherwise `metadata.component.version` in the SBOM.

The request fails with `400` if neither is set. Pushing the same version again replaces its SBOM, so re-running a release pipeline is safe.

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
    curl --fail-with-body -X POST "$TOCSIN_URL/api/sboms?version=${GITHUB_REF_NAME}" \
      -H "Authorization: Bearer ${{ secrets.TOCSIN_TOKEN }}" \
      -H "Content-Type: application/json" \
      --data-binary @bom.json
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
      curl --fail-with-body -X POST "$TOCSIN_URL/api/sboms?version=$CI_COMMIT_TAG"
      -H "Authorization: Bearer $TOCSIN_TOKEN"
      -H "Content-Type: application/json"
      --data-binary @bom.json
  variables:
    TOCSIN_URL: https://tocsin.example.com
```

## Troubleshooting

| Response | Cause |
|---|---|
| `401 invalid or missing bearer token` | The token is wrong, or the `Authorization: Bearer …` header is missing. |
| `400 release version missing` | Neither `?version=` nor `metadata.component.version` is set. |
| `400 unsupported bomFormat` / `invalid CycloneDX document` | The file is not CycloneDX JSON (SPDX and XML are not supported). |
| `413 Payload Too Large` | The SBOM is over 50 MB. |
| `415 Unsupported Media Type` | The `Content-Type: application/json` header is missing. |
