use std::{collections::BTreeMap, fs, path::Path};

use anyhow::{Context, Result, bail};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};

use crate::analyzer::{Finding, FindingSeverity, RiskLevel};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Deserialize, Serialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum UiLocale {
    #[default]
    En,
    Ru,
}

#[derive(Debug, Clone)]
pub struct UiText {
    locale: UiLocale,
    values: BTreeMap<String, String>,
}

impl UiText {
    pub fn load(locale: UiLocale, path: Option<&Path>) -> Result<Self> {
        let mut values = builtin(locale);

        if let Some(path) = path {
            let overrides = load_overrides(path)?;
            values.extend(overrides);
        }

        Ok(Self { locale, values })
    }

    pub fn locale(&self) -> UiLocale {
        self.locale
    }

    pub fn text(&self, key: &'static str) -> &str {
        self.values.get(key).map(String::as_str).unwrap_or(key)
    }

    pub fn status(&self, value: bool) -> &str {
        if value {
            self.text("status.yes")
        } else {
            self.text("status.no")
        }
    }

    pub fn none(&self) -> &str {
        self.text("status.none")
    }

    pub fn severity(&self, severity: &FindingSeverity) -> &str {
        match severity {
            FindingSeverity::Info => self.text("severity.info"),
            FindingSeverity::Low => self.text("severity.low"),
            FindingSeverity::Medium => self.text("severity.medium"),
            FindingSeverity::High => self.text("severity.high"),
        }
    }

    pub fn risk(&self, level: &RiskLevel) -> &str {
        match level {
            RiskLevel::Low => self.text("risk.low"),
            RiskLevel::Medium => self.text("risk.medium"),
            RiskLevel::High => self.text("risk.high"),
            RiskLevel::Critical => self.text("risk.critical"),
        }
    }

    pub fn finding_title<'a>(&'a self, finding: &'a Finding) -> &'a str {
        let key = format!("finding.{}.title", finding.code);
        self.values
            .get(&key)
            .map(String::as_str)
            .unwrap_or(finding.title)
    }
}

impl UiLocale {
    pub fn code(self) -> &'static str {
        match self {
            UiLocale::En => "en",
            UiLocale::Ru => "ru",
        }
    }
}

fn load_overrides(path: &Path) -> Result<BTreeMap<String, String>> {
    let contents = fs::read_to_string(path)
        .with_context(|| format!("failed to read UI locale file {}", path.display()))?;
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();

    match extension.as_str() {
        "json" => serde_json::from_str(&contents)
            .with_context(|| format!("failed to parse JSON UI locale {}", path.display())),
        "yaml" | "yml" => serde_yaml::from_str(&contents)
            .with_context(|| format!("failed to parse YAML UI locale {}", path.display())),
        _ => bail!(
            "unsupported UI locale extension for {}; expected .json, .yaml, or .yml",
            path.display()
        ),
    }
}

fn builtin(locale: UiLocale) -> BTreeMap<String, String> {
    match locale {
        UiLocale::En => en(),
        UiLocale::Ru => ru(),
    }
}

fn en() -> BTreeMap<String, String> {
    map([
        ("scan.title", "AVRORA Compliance Scan"),
        ("label.target", "Target"),
        ("label.http_status", "HTTP status"),
        ("label.legal_locale", "Legal locale"),
        ("label.ui_locale", "UI locale"),
        ("label.response", "Response"),
        ("label.content_type", "Content-Type"),
        ("section.detected_features", "Detected Features"),
        ("section.security", "Security Headers"),
        ("section.findings", "Findings"),
        ("section.legal", "Legal Rule Evaluation"),
        ("label.consent_checkbox", "Consent checkbox"),
        ("label.prechecked_consent", "Pre-checked consent"),
        ("label.cookie_banner", "Cookie banner"),
        ("label.cookie_indicators", "Cookie indicators"),
        ("label.privacy_policy_link", "Privacy policy link"),
        ("label.forms", "Forms"),
        ("label.scripts", "Scripts"),
        ("label.document", "Document"),
        ("label.links", "Links"),
        ("label.title", "title"),
        ("label.lang", "lang"),
        ("label.viewport", "viewport"),
        ("label.canonical", "canonical"),
        ("label.noindex", "noindex"),
        ("label.total", "total"),
        ("label.external", "external"),
        ("label.insecure", "insecure"),
        ("label.terms", "terms"),
        ("label.analytics", "Analytics providers"),
        ("label.risk", "Risk"),
        ("label.code", "Code"),
        ("label.evidence", "Evidence"),
        ("label.severity", "severity"),
        ("status.yes", "yes"),
        ("status.no", "no"),
        ("status.none", "none"),
        ("severity.info", "[info]"),
        ("severity.low", "[low]"),
        ("severity.medium", "[medium]"),
        ("severity.high", "[high]"),
        ("risk.low", "low"),
        ("risk.medium", "medium"),
        ("risk.high", "high"),
        ("risk.critical", "critical"),
        (
            "message.no_applicable_rules",
            "No applicable legal rules matched this scan.",
        ),
        ("message.rules_valid", "Rules file is valid"),
    ])
}

fn ru() -> BTreeMap<String, String> {
    map([
        ("scan.title", "AVRORA: проверка соответствия"),
        ("label.target", "Цель"),
        ("label.http_status", "HTTP-статус"),
        ("label.legal_locale", "Правовая локаль"),
        ("label.ui_locale", "Язык интерфейса"),
        ("label.response", "Ответ"),
        ("label.content_type", "Content-Type"),
        ("section.detected_features", "Обнаруженные признаки"),
        ("section.security", "Заголовки безопасности"),
        ("section.findings", "Нарушения и риски"),
        ("section.legal", "Проверка правовых правил"),
        ("label.consent_checkbox", "Checkbox согласия"),
        ("label.prechecked_consent", "Согласие отмечено заранее"),
        ("label.cookie_banner", "Cookie-баннер"),
        ("label.cookie_indicators", "Признаки cookies"),
        ("label.privacy_policy_link", "Ссылка на политику"),
        ("label.forms", "Формы"),
        ("label.scripts", "Скрипты"),
        ("label.document", "Документ"),
        ("label.links", "Ссылки"),
        ("label.title", "title"),
        ("label.lang", "lang"),
        ("label.viewport", "viewport"),
        ("label.canonical", "canonical"),
        ("label.noindex", "noindex"),
        ("label.total", "всего"),
        ("label.external", "внешних"),
        ("label.insecure", "небезопасных"),
        ("label.terms", "условия"),
        ("label.analytics", "Провайдеры аналитики"),
        ("label.risk", "Риск"),
        ("label.code", "Код"),
        ("label.evidence", "Доказательство"),
        ("label.severity", "критичность"),
        ("status.yes", "да"),
        ("status.no", "нет"),
        ("status.none", "нет"),
        ("severity.info", "[инфо]"),
        ("severity.low", "[низкий]"),
        ("severity.medium", "[средний]"),
        ("severity.high", "[высокий]"),
        ("risk.low", "низкий"),
        ("risk.medium", "средний"),
        ("risk.high", "высокий"),
        ("risk.critical", "критический"),
        (
            "message.no_applicable_rules",
            "Нет применимых правовых правил для этого скана.",
        ),
        ("message.rules_valid", "Файл правил корректен"),
        (
            "finding.analytics_without_explicit_consent_control.title",
            "Аналитика обнаружена без явного элемента согласия",
        ),
        (
            "finding.cookie_signals_without_visible_notice.title",
            "Признаки cookies обнаружены без видимого уведомления",
        ),
        (
            "finding.pre_checked_consent_control.title",
            "Checkbox согласия, вероятно, отмечен заранее",
        ),
        (
            "finding.forms_without_privacy_policy_link.title",
            "Формы с персональными данными обнаружены без видимой ссылки на политику",
        ),
        (
            "finding.insecure_form_action.title",
            "Форма отправляет данные на небезопасный HTTP endpoint",
        ),
        (
            "finding.third_party_tracking_cookie_surface.title",
            "Одновременно обнаружены third-party tracking и cookie surface",
        ),
        (
            "finding.tracking_pixels_without_consent_control.title",
            "Tracking pixel обнаружен без явного элемента согласия",
        ),
        (
            "finding.no_material_mvp_findings.title",
            "Существенных MVP-нарушений не обнаружено",
        ),
        (
            "finding.weak_security_header_posture.title",
            "Отсутствуют несколько важных заголовков безопасности",
        ),
        (
            "finding.mixed_content_or_insecure_links.title",
            "На странице обнаружены HTTP-ресурсы или небезопасные ссылки",
        ),
        (
            "finding.missing_document_language.title",
            "Язык документа не указан",
        ),
    ])
}

fn map<const N: usize>(pairs: [(&'static str, &'static str); N]) -> BTreeMap<String, String> {
    pairs
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect()
}
