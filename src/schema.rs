use std::{fs, path::Path};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct PolicySchema {
    #[serde(default)]
    pub company_name: Option<String>,

    #[serde(default)]
    pub storage_location: Option<String>,

    #[serde(default)]
    pub data_types: Vec<DataType>,

    #[serde(default)]
    pub purposes: Vec<Purpose>,

    #[serde(default)]
    pub third_parties: Vec<ThirdParty>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DataType {
    pub name: String,
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Purpose {
    pub name: String,
    #[serde(default)]
    pub legal_basis: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ThirdParty {
    pub name: String,
    #[serde(default)]
    pub purpose: Option<String>,
    #[serde(default)]
    pub country: Option<String>,
}

pub fn load_optional_schema(path: Option<&Path>) -> Result<Option<PolicySchema>> {
    path.map(load_schema).transpose()
}

pub fn load_schema(path: &Path) -> Result<PolicySchema> {
    let contents = fs::read_to_string(path)
        .with_context(|| format!("failed to read schema file {}", path.display()))?;

    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();

    match extension.as_str() {
        "json" => serde_json::from_str(&contents)
            .with_context(|| format!("failed to parse JSON schema {}", path.display())),
        "yaml" | "yml" => serde_yaml::from_str(&contents)
            .with_context(|| format!("failed to parse YAML schema {}", path.display())),
        _ => bail!(
            "unsupported schema extension for {}; expected .json, .yaml, or .yml",
            path.display()
        ),
    }
}
