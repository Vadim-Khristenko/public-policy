use std::collections::BTreeMap;

use anyhow::{Result, bail};

use crate::documents::DocumentType;
use crate::locale::Locale;

const EN_PRIVACY_TEMPLATE: &str = include_str!("../templates/en/privacy.md");
const RU_PRIVACY_TEMPLATE: &str = include_str!("../templates/ru/privacy.md");
const US_CA_PRIVACY_TEMPLATE: &str = include_str!("../templates/us-ca/privacy.md");
const EN_COOKIE_TEMPLATE: &str = include_str!("../templates/en/cookie.md");
const RU_COOKIE_TEMPLATE: &str = include_str!("../templates/ru/cookie.md");
const US_CA_COOKIE_TEMPLATE: &str = include_str!("../templates/us-ca/cookie.md");
const EN_NOTICE_TEMPLATE: &str = include_str!("../templates/en/processing-notice.md");
const RU_NOTICE_TEMPLATE: &str = include_str!("../templates/ru/processing-notice.md");
const US_CA_NOTICE_TEMPLATE: &str = include_str!("../templates/us-ca/processing-notice.md");

#[derive(Debug, Clone)]
pub struct Template {
    body: &'static str,
}

impl Template {
    pub fn document(locale: Locale, document_type: DocumentType) -> Self {
        let body = match locale {
            Locale::En => match document_type {
                DocumentType::Privacy => EN_PRIVACY_TEMPLATE,
                DocumentType::Cookie => EN_COOKIE_TEMPLATE,
                DocumentType::ProcessingNotice => EN_NOTICE_TEMPLATE,
            },
            Locale::Ru => match document_type {
                DocumentType::Privacy => RU_PRIVACY_TEMPLATE,
                DocumentType::Cookie => RU_COOKIE_TEMPLATE,
                DocumentType::ProcessingNotice => RU_NOTICE_TEMPLATE,
            },
            Locale::UsCa => match document_type {
                DocumentType::Privacy => US_CA_PRIVACY_TEMPLATE,
                DocumentType::Cookie => US_CA_COOKIE_TEMPLATE,
                DocumentType::ProcessingNotice => US_CA_NOTICE_TEMPLATE,
            },
        };
        Self { body }
    }

    pub fn render(&self, variables: &TemplateVariables) -> Result<String> {
        let mut rendered = self.body.to_owned();

        for (key, value) in &variables.values {
            let token = format!("{{{{{key}}}}}");
            rendered = rendered.replace(&token, value);
        }

        if let Some(unresolved) = find_unresolved_token(&rendered) {
            bail!("unresolved template variable: {unresolved}");
        }

        Ok(rendered)
    }
}

#[derive(Debug, Clone, Default)]
pub struct TemplateVariables {
    values: BTreeMap<String, String>,
}

impl TemplateVariables {
    pub fn insert(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.values.insert(key.into(), value.into());
    }
}

fn find_unresolved_token(rendered: &str) -> Option<&str> {
    let start = rendered.find("{{")?;
    let tail = &rendered[start..];
    let end = tail.find("}}")?;
    Some(&tail[..end + 2])
}
