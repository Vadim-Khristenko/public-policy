use std::{fmt, str::FromStr};

use clap::ValueEnum;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Deserialize, Serialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Locale {
    #[default]
    En,
    Ru,
    #[serde(rename = "us-ca")]
    #[value(name = "us-ca")]
    UsCa,
}

impl Locale {
    pub fn code(self) -> &'static str {
        match self {
            Locale::En => "en",
            Locale::Ru => "ru",
            Locale::UsCa => "us-ca",
        }
    }

    pub fn legal_framework(self) -> &'static str {
        match self {
            Locale::En => "GDPR-style",
            Locale::Ru => "152-FZ",
            Locale::UsCa => "CCPA/CPRA",
        }
    }
}

impl fmt::Display for Locale {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl FromStr for Locale {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "en" => Ok(Locale::En),
            "ru" => Ok(Locale::Ru),
            "us-ca" | "us_ca" | "ca" | "ccpa" => Ok(Locale::UsCa),
            other => Err(format!(
                "unsupported locale `{other}`; expected `en`, `ru`, or `us-ca`"
            )),
        }
    }
}
