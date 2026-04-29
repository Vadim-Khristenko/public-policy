use std::{collections::BTreeMap, fs, path::Path};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::{analyzer::DetectedFeatures, locale::Locale, schema::PolicySchema};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LegalRule {
    pub id: String,
    pub condition: Condition,
    pub requirement: LocalizedRequirement,
    pub severity: u8,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LocalizedRequirement {
    #[serde(flatten)]
    values: BTreeMap<String, String>,
}

impl LocalizedRequirement {
    pub fn single(value: impl Into<String>) -> Self {
        let mut values = BTreeMap::new();
        values.insert("en".to_owned(), value.into());
        Self { values }
    }

    pub fn localized(en: &'static str, ru: &'static str, us_ca: &'static str) -> Self {
        let mut values = BTreeMap::new();
        values.insert("en".to_owned(), en.to_owned());
        values.insert("ru".to_owned(), ru.to_owned());
        values.insert("us-ca".to_owned(), us_ca.to_owned());
        Self { values }
    }

    pub fn resolve(&self, locale: Locale) -> String {
        self.values
            .get(locale.code())
            .or_else(|| self.values.get("en"))
            .or_else(|| self.values.values().next())
            .cloned()
            .unwrap_or_default()
    }

    fn is_empty(&self) -> bool {
        self.values.values().all(|value| value.trim().is_empty())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Condition {
    Always,
    AnalyticsPresent,
    CookiesPresent,
    ConsentMissing,
    PreCheckedConsent,
    PrivacyPolicyMissing,
    OptOutLinkMissing,
    GpcReferenceMissing,
    PrivacyContactMissing,
    RetentionReferenceMissing,
    AiDisclosureMissing,
    SecurityContactMissing,
    FormsCollectPersonalData,
    SensitiveInputsPresent,
    StorageOutsideRussia,
    DeclaredPurposesMissing,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuleEvaluation {
    pub rule_id: String,
    pub applies: bool,
    pub requirement: String,
    pub severity: u8,
}

#[derive(Debug, Deserialize)]
struct RawRule {
    id: String,
    condition: String,
    #[serde(default)]
    requirement: String,
    #[serde(default)]
    requirements: BTreeMap<String, String>,
    severity: u8,
}

pub fn builtin_rules(locale: Locale) -> Vec<LegalRule> {
    match locale {
        Locale::En => gdpr_rules(),
        Locale::Ru => russian_152fz_rules(),
        Locale::UsCa => ccpa_cpra_rules(),
    }
}

pub fn evaluate_rules(
    features: &DetectedFeatures,
    locale: Locale,
    schema: Option<&PolicySchema>,
    custom_rules: &[LegalRule],
) -> Vec<RuleEvaluation> {
    builtin_rules(locale)
        .into_iter()
        .chain(custom_rules.iter().cloned())
        .map(|rule| RuleEvaluation {
            applies: rule.condition.matches(features, schema),
            rule_id: rule.id,
            requirement: rule.requirement.resolve(locale),
            severity: rule.severity,
        })
        .collect()
}

pub fn load_optional_rules(path: Option<&Path>) -> Result<Vec<LegalRule>> {
    path.map(load_rules)
        .transpose()
        .map(Option::unwrap_or_default)
}

pub fn load_rules(path: &Path) -> Result<Vec<LegalRule>> {
    let contents = fs::read_to_string(path)
        .with_context(|| format!("failed to read rules file {}", path.display()))?;
    let raw_rules: Vec<RawRule> = serde_yaml::from_str(&contents)
        .with_context(|| format!("failed to parse YAML rules {}", path.display()))?;

    raw_rules
        .into_iter()
        .map(|rule| {
            Ok(LegalRule {
                id: rule.id,
                condition: parse_condition(&rule.condition)?,
                requirement: raw_requirement(rule.requirement, rule.requirements),
                severity: rule.severity,
            })
        })
        .collect()
}

pub fn validate_rules(rules: &[LegalRule]) -> Result<()> {
    for rule in rules {
        if rule.id.trim().is_empty() {
            bail!("rule id must not be empty");
        }

        if rule.requirement.is_empty() {
            bail!("rule `{}` requirement must not be empty", rule.id);
        }

        if rule.severity > 100 {
            bail!("rule `{}` severity must be between 0 and 100", rule.id);
        }
    }

    Ok(())
}

impl Condition {
    fn matches(&self, features: &DetectedFeatures, schema: Option<&PolicySchema>) -> bool {
        match self {
            Condition::Always => true,
            Condition::AnalyticsPresent => !features.analytics.is_empty(),
            Condition::CookiesPresent => features.cookie_indicators,
            Condition::ConsentMissing => !features.consent_checkbox,
            Condition::PreCheckedConsent => features.pre_checked_consent,
            Condition::PrivacyPolicyMissing => !features.privacy_policy_link,
            Condition::OptOutLinkMissing => !features.opt_out_link,
            Condition::GpcReferenceMissing => !features.gpc_signal_reference,
            Condition::PrivacyContactMissing => !features.privacy_contact,
            Condition::RetentionReferenceMissing => !features.retention_reference,
            Condition::AiDisclosureMissing => {
                features.ai_system_reference && !features.ai_disclosure_reference
            }
            Condition::SecurityContactMissing => !features.security_contact_reference,
            Condition::FormsCollectPersonalData => features.forms.collects_personal_data(),
            Condition::SensitiveInputsPresent => features.forms.may_collect_sensitive_data(),
            Condition::StorageOutsideRussia => schema
                .and_then(|schema| schema.storage_location.as_deref())
                .is_none_or(|location| !location.to_ascii_lowercase().contains("russia")),
            Condition::DeclaredPurposesMissing => {
                schema.is_none_or(|schema| schema.purposes.is_empty())
            }
        }
    }
}

fn gdpr_rules() -> Vec<LegalRule> {
    vec![
        rule_i18n(
            "gdpr_lawful_basis_required",
            Condition::Always,
            "A lawful basis must be documented for each personal-data processing activity.",
            "Для каждой операции обработки персональных данных должно быть документировано правовое основание.",
            "A lawful basis must be documented for each personal-information processing activity.",
            80,
        ),
        rule_i18n(
            "gdpr_consent_or_legitimate_interest",
            Condition::AnalyticsPresent,
            "Analytics or tracking must rely on documented consent or a documented legitimate-interest assessment.",
            "Аналитика или tracking должны опираться на документированное согласие либо оценку законного интереса.",
            "Analytics or tracking must rely on documented consent or another documented permitted basis.",
            75,
        ),
        rule_i18n(
            "gdpr_right_of_access",
            Condition::Always,
            "The policy must explain the user's right of access to personal data.",
            "Политика должна объяснять право пользователя на доступ к персональным данным.",
            "The policy must explain the consumer's right to access personal information where applicable.",
            60,
        ),
        rule_i18n(
            "gdpr_right_to_erasure",
            Condition::Always,
            "The policy must explain the user's right to erasure where legal grounds apply.",
            "Политика должна объяснять право пользователя на удаление данных, когда применимы правовые основания.",
            "The policy must explain deletion rights where applicable.",
            60,
        ),
        rule_i18n(
            "gdpr_transparency",
            Condition::Always,
            "Processing must be transparent, with clear information about controllers, purposes, data categories, recipients, and retention.",
            "Обработка должна быть прозрачной: контроллеры, цели, категории данных, получатели и сроки хранения должны быть понятны пользователю.",
            "Processing must be transparent, with clear information about business purposes, categories, recipients, and retention.",
            70,
        ),
        rule_i18n(
            "gdpr_privacy_contact_required",
            Condition::PrivacyContactMissing,
            "A privacy contact or responsible data-protection contact should be disclosed.",
            "Должен быть указан контакт по вопросам приватности или ответственное лицо по защите данных.",
            "A privacy contact should be disclosed for consumer requests.",
            65,
        ),
        rule_i18n(
            "gdpr_retention_transparency",
            Condition::RetentionReferenceMissing,
            "Retention periods or retention criteria should be disclosed.",
            "Сроки хранения или критерии определения сроков хранения должны быть раскрыты.",
            "Retention periods or criteria should be disclosed where required.",
            65,
        ),
        rule_i18n(
            "gdpr_purpose_limitation",
            Condition::DeclaredPurposesMissing,
            "Processing purposes must be specific, explicit, legitimate, and declared before processing.",
            "Цели обработки должны быть конкретными, явными, законными и заявленными до начала обработки.",
            "Collection and use purposes must be disclosed before or at collection.",
            80,
        ),
        rule_i18n(
            "pecr_cookie_notice_and_consent",
            Condition::CookiesPresent,
            "Cookies and similar technologies must be explained clearly and non-essential storage/access must be based on actively given consent unless an exemption applies.",
            "Cookies и аналогичные технологии должны быть ясно описаны; необязательное хранение или доступ требуют активного согласия, если нет исключения.",
            "Cookies and similar technologies must be disclosed, and non-essential tracking should be controlled by opt-out or consent mechanisms where required.",
            80,
        ),
        rule_i18n(
            "pecr_no_nonessential_cookies_before_consent",
            Condition::ConsentMissing,
            "Non-essential cookies should not be set before valid user consent.",
            "Необязательные cookies не должны устанавливаться до получения действительного согласия пользователя.",
            "Non-essential tracking should not run before the applicable user choice is handled.",
            75,
        ),
    ]
}

fn ccpa_cpra_rules() -> Vec<LegalRule> {
    vec![
        rule_i18n(
            "ccpa_notice_at_collection",
            Condition::FormsCollectPersonalData,
            "A notice at collection must disclose categories of personal information and purposes at or before collection.",
            "Уведомление при сборе должно раскрывать категории персональной информации и цели до или в момент сбора.",
            "A notice at collection must disclose categories of personal information and purposes at or before collection.",
            85,
        ),
        rule_i18n(
            "ccpa_privacy_policy_required",
            Condition::PrivacyPolicyMissing,
            "A privacy policy must disclose consumer rights, categories collected, sources, purposes, third-party disclosures, and request methods.",
            "Политика конфиденциальности должна раскрывать права потребителей, категории данных, источники, цели, передачи третьим лицам и способы подачи запросов.",
            "A privacy policy must disclose consumer rights, categories collected, sources, purposes, third-party disclosures, and request methods.",
            80,
        ),
        rule_i18n(
            "ccpa_opt_out_sale_share_link",
            Condition::OptOutLinkMissing,
            "If personal information is sold or shared, a clear Do Not Sell or Share My Personal Information link or equivalent opt-out path must be available.",
            "Если персональная информация продается или передается для cross-context advertising, должен быть доступен понятный opt-out путь.",
            "If personal information is sold or shared, a clear Do Not Sell or Share My Personal Information link or equivalent opt-out path must be available.",
            75,
        ),
        rule_i18n(
            "ccpa_gpc_recognition",
            Condition::GpcReferenceMissing,
            "Businesses subject to CCPA should be prepared to honor user-enabled global privacy controls for sale/share opt-out requests.",
            "Компании, подпадающие под CCPA, должны быть готовы учитывать Global Privacy Control как запрос opt-out.",
            "Businesses subject to CCPA should be prepared to honor user-enabled global privacy controls for sale/share opt-out requests.",
            70,
        ),
        rule_i18n(
            "ccpa_privacy_contact_methods",
            Condition::PrivacyContactMissing,
            "Consumer request methods and privacy contact channels should be disclosed.",
            "Должны быть раскрыты способы подачи consumer requests и каналы связи по приватности.",
            "Consumer request methods and privacy contact channels should be disclosed.",
            70,
        ),
        rule_i18n(
            "ccpa_retention_disclosure",
            Condition::RetentionReferenceMissing,
            "Retention periods or retention criteria for personal information should be disclosed.",
            "Сроки хранения или критерии хранения персональной информации должны быть раскрыты.",
            "Retention periods or retention criteria for personal information should be disclosed.",
            70,
        ),
        rule_i18n(
            "cpra_sensitive_information_limit",
            Condition::SensitiveInputsPresent,
            "Sensitive personal information processing requires disclosure and, where applicable, a right to limit use and disclosure.",
            "Обработка sensitive personal information требует раскрытия и, где применимо, права ограничить использование и раскрытие.",
            "Sensitive personal information processing requires disclosure and, where applicable, a right to limit use and disclosure.",
            80,
        ),
        rule_i18n(
            "ccpa_non_discrimination",
            Condition::Always,
            "Consumers must not be discriminated against for exercising CCPA rights.",
            "Потребителей нельзя дискриминировать за реализацию прав по CCPA.",
            "Consumers must not be discriminated against for exercising CCPA rights.",
            60,
        ),
    ]
}

fn russian_152fz_rules() -> Vec<LegalRule> {
    vec![
        rule_i18n(
            "ru_152fz_explicit_consent_before_processing",
            Condition::FormsCollectPersonalData,
            "Explicit consent or another valid legal ground is required before personal-data processing starts.",
            "До начала обработки персональных данных требуется явное согласие субъекта либо иное допустимое законом основание.",
            "Explicit consent or another valid legal ground is required before personal-information processing starts.",
            90,
        ),
        rule_i18n(
            "ru_152fz_checkbox_must_not_be_prechecked",
            Condition::PreCheckedConsent,
            "Consent checkbox must not be pre-checked; consent must be an active user action.",
            "Поле согласия не должно быть предварительно отмечено; согласие должно выражаться активным действием пользователя.",
            "Consent checkbox must not be pre-checked; consent must be an active user action.",
            95,
        ),
        rule_i18n(
            "ru_152fz_privacy_policy_required",
            Condition::PrivacyPolicyMissing,
            "A personal-data processing policy must be published and available to users.",
            "Политика обработки персональных данных должна быть опубликована и доступна пользователю до начала обработки.",
            "A privacy policy must be published and available to users before collection.",
            85,
        ),
        rule_i18n(
            "ru_152fz_data_localization_required",
            Condition::StorageOutsideRussia,
            "Russian citizens' personal data must be processed using databases located in Russia unless a statutory exception applies.",
            "Персональные данные граждан Российской Федерации должны записываться, систематизироваться, накапливаться, храниться, уточняться и извлекаться с использованием баз данных на территории Российской Федерации, если не применяется законное исключение.",
            "Russian citizens' personal data must be processed using databases located in Russia unless a statutory exception applies.",
            95,
        ),
        rule_i18n(
            "ru_152fz_2025_primary_collection_ru_databases",
            Condition::StorageOutsideRussia,
            "From 2025, primary collection operations must use Russian databases across applicable operator and processor chains.",
            "С 2025 года первичные операции сбора персональных данных должны выполняться с использованием российских баз данных; требование учитывается для операторов и обработчиков в применимой цепочке обработки.",
            "From 2025, primary collection operations must use Russian databases across applicable operator and processor chains.",
            95,
        ),
        rule_i18n(
            "ru_152fz_declared_purposes_only",
            Condition::DeclaredPurposesMissing,
            "Personal data must be processed only for declared and lawful purposes.",
            "Персональные данные должны обрабатываться только для заранее заявленных и законных целей.",
            "Personal information must be processed only for declared and lawful purposes.",
            90,
        ),
        rule_i18n(
            "ru_152fz_privacy_contact_required",
            Condition::PrivacyContactMissing,
            "A responsible contact for personal-data processing requests should be disclosed.",
            "Должен быть указан контакт или ответственное лицо для обращений субъектов персональных данных.",
            "A responsible contact for personal-data processing requests should be disclosed.",
            75,
        ),
        rule_i18n(
            "ai_act_transparency_for_ai_systems",
            Condition::AiDisclosureMissing,
            "AI or automated-decision functionality should include clear transparency disclosure where applicable.",
            "Функции ИИ или автоматизированного принятия решений должны сопровождаться понятным раскрытием, если это применимо.",
            "AI or automated-decision functionality should include clear transparency disclosure where applicable.",
            75,
        ),
        rule_i18n(
            "security_incident_contact",
            Condition::SecurityContactMissing,
            "Security or incident contact information should be available for vulnerability and incident handling.",
            "Должен быть доступен контакт по вопросам безопасности, уязвимостей или инцидентов.",
            "Security or incident contact information should be available for vulnerability and incident handling.",
            55,
        ),
    ]
}

fn rule_i18n(
    id: &'static str,
    condition: Condition,
    en: &'static str,
    ru: &'static str,
    us_ca: &'static str,
    severity: u8,
) -> LegalRule {
    LegalRule {
        id: id.to_owned(),
        condition,
        requirement: LocalizedRequirement::localized(en, ru, us_ca),
        severity,
    }
}

fn raw_requirement(
    requirement: String,
    mut requirements: BTreeMap<String, String>,
) -> LocalizedRequirement {
    if requirements.is_empty() {
        return LocalizedRequirement::single(requirement);
    }

    if !requirement.trim().is_empty() {
        requirements.entry("en".to_owned()).or_insert(requirement);
    }

    LocalizedRequirement {
        values: requirements,
    }
}

fn parse_condition(condition: &str) -> Result<Condition> {
    match condition.trim().to_ascii_lowercase().as_str() {
        "always" | "true" => Ok(Condition::Always),
        "analytics == true" | "analytics_present" => Ok(Condition::AnalyticsPresent),
        "cookies == true" | "cookies_present" => Ok(Condition::CookiesPresent),
        "consent == false" | "consent_missing" => Ok(Condition::ConsentMissing),
        "pre_checked_consent == true" | "pre_checked_consent" => Ok(Condition::PreCheckedConsent),
        "privacy_policy == false" | "privacy_policy_missing" => Ok(Condition::PrivacyPolicyMissing),
        "opt_out_link == false" | "opt_out_link_missing" => Ok(Condition::OptOutLinkMissing),
        "gpc_reference == false" | "gpc_reference_missing" => Ok(Condition::GpcReferenceMissing),
        "privacy_contact == false" | "privacy_contact_missing" => {
            Ok(Condition::PrivacyContactMissing)
        }
        "retention_reference == false" | "retention_reference_missing" => {
            Ok(Condition::RetentionReferenceMissing)
        }
        "ai_disclosure == false" | "ai_disclosure_missing" => Ok(Condition::AiDisclosureMissing),
        "security_contact == false" | "security_contact_missing" => {
            Ok(Condition::SecurityContactMissing)
        }
        "forms_collect_personal_data == true" | "forms_collect_personal_data" => {
            Ok(Condition::FormsCollectPersonalData)
        }
        "sensitive_inputs == true" | "sensitive_inputs_present" => {
            Ok(Condition::SensitiveInputsPresent)
        }
        "storage_location != russia" | "storage_outside_russia" => {
            Ok(Condition::StorageOutsideRussia)
        }
        "declared_purposes == false" | "declared_purposes_missing" => {
            Ok(Condition::DeclaredPurposesMissing)
        }
        other => bail!("unsupported rule condition `{other}`"),
    }
}
