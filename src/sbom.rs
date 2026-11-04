use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

// ponytail: only the CycloneDX fields Tocsin uses; the raw document is stored as-is
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Bom {
    bom_format: String,
    metadata: Option<Metadata>,
    #[serde(default)]
    components: Vec<Component>,
}

#[derive(Deserialize)]
struct Metadata {
    component: Option<Component>,
}

#[derive(Deserialize)]
struct Component {
    version: Option<String>,
    purl: Option<String>,
    #[serde(default)]
    licenses: Vec<LicenseChoice>,
    #[serde(default)]
    components: Vec<Component>,
}

/// CycloneDX `licenses` item: `{"license": {"id"|"name"}}` or `{"expression": "..."}`.
#[derive(Deserialize)]
struct LicenseChoice {
    license: Option<License>,
    expression: Option<String>,
}

#[derive(Deserialize)]
struct License {
    id: Option<String>,
    name: Option<String>,
}

pub struct Parsed {
    /// Version of the released software (metadata.component.version)
    pub version: Option<String>,
    /// Deduplicated purls of all components, nested ones included, with their licenses
    pub components: BTreeMap<String, BTreeSet<String>>,
}

pub fn parse(doc: &serde_json::Value) -> Result<Parsed, String> {
    let bom = Bom::deserialize(doc).map_err(|e| format!("invalid CycloneDX document: {e}"))?;
    if bom.bom_format != "CycloneDX" {
        return Err(format!("unsupported bomFormat: {}", bom.bom_format));
    }
    let mut components = BTreeMap::new();
    collect(&bom.components, &mut components);
    Ok(Parsed {
        version: bom
            .metadata
            .and_then(|m| m.component)
            .and_then(|c| c.version),
        components,
    })
}

// Components without purl can't be matched against vulnerability databases: skipped.
fn collect(components: &[Component], out: &mut BTreeMap<String, BTreeSet<String>>) {
    for c in components {
        if let Some(purl) = &c.purl {
            let licenses = out.entry(purl.clone()).or_default();
            for choice in &c.licenses {
                let license = choice
                    .license
                    .as_ref()
                    .and_then(|l| l.id.as_ref().or(l.name.as_ref()))
                    .or(choice.expression.as_ref());
                if let Some(l) = license.map(|l| l.trim()).filter(|l| !l.is_empty()) {
                    licenses.insert(l.to_owned());
                }
            }
        }
        collect(&c.components, out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn rejects_non_cyclonedx() {
        assert!(parse(&json!({"bomFormat": "SPDX"})).is_err());
        assert!(parse(&json!({"spdxVersion": "SPDX-2.3"})).is_err());
    }

    #[test]
    fn extracts_licenses() {
        let parsed = parse(&json!({
            "bomFormat": "CycloneDX",
            "components": [
                { "purl": "pkg:npm/a@1", "licenses": [{ "license": { "id": "MIT" } }] },
                { "purl": "pkg:npm/b@1", "licenses": [{ "license": { "name": "Custom" } }, { "expression": "GPL-2.0-only OR MIT" }] },
                { "purl": "pkg:npm/c@1" }
            ]
        }))
        .unwrap();
        let get = |p: &str| parsed.components[p].iter().cloned().collect::<Vec<_>>();
        assert_eq!(get("pkg:npm/a@1"), ["MIT"]);
        assert_eq!(get("pkg:npm/b@1"), ["Custom", "GPL-2.0-only OR MIT"]);
        assert!(get("pkg:npm/c@1").is_empty());
    }
}
