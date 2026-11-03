use serde::Deserialize;
use std::collections::BTreeSet;

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
    components: Vec<Component>,
}

pub struct Parsed {
    /// Version of the released software (metadata.component.version)
    pub version: Option<String>,
    /// Deduplicated purls of all components, nested ones included
    pub purls: BTreeSet<String>,
}

pub fn parse(doc: &serde_json::Value) -> Result<Parsed, String> {
    let bom = Bom::deserialize(doc).map_err(|e| format!("invalid CycloneDX document: {e}"))?;
    if bom.bom_format != "CycloneDX" {
        return Err(format!("unsupported bomFormat: {}", bom.bom_format));
    }
    let mut purls = BTreeSet::new();
    collect(&bom.components, &mut purls);
    Ok(Parsed {
        version: bom
            .metadata
            .and_then(|m| m.component)
            .and_then(|c| c.version),
        purls,
    })
}

// Components without purl can't be matched against vulnerability databases: skipped.
fn collect(components: &[Component], out: &mut BTreeSet<String>) {
    for c in components {
        if let Some(purl) = &c.purl {
            out.insert(purl.clone());
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
}
