use scraper::{Html, Selector};
use serde::Serialize;
use thiserror::Error;

use crate::scanner::ScanResult;

const RISK_ANALYTICS_WITHOUT_CONSENT: u16 = 45;
const RISK_MISSING_COOKIE_NOTICE: u16 = 25;
const RISK_TRACKING_WITH_COOKIE_SIGNALS: u16 = 15;
const RISK_PRECHECKED_CONSENT: u16 = 35;
const RISK_FORMS_WITHOUT_POLICY: u16 = 30;
const RISK_INSECURE_FORM_ACTION: u16 = 30;
const RISK_MISSING_SECURITY_HEADERS: u16 = 20;
const RISK_MIXED_CONTENT: u16 = 20;
const RISK_MISSING_DOCUMENT_LANGUAGE: u16 = 10;
const MAX_RISK_SCORE: u16 = 100;

#[derive(Debug, Clone, Serialize)]
pub struct AnalysisReport {
    pub target: TargetMetadata,
    pub features: DetectedFeatures,
    pub findings: Vec<Finding>,
    pub risk: RiskAssessment,
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetMetadata {
    pub requested_url: String,
    pub final_url: String,
    pub status: u16,
    pub content_type: Option<String>,
    pub elapsed_ms: u128,
    pub response_bytes: usize,
    pub security_headers: crate::scanner::SecurityHeaders,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct DetectedFeatures {
    pub consent_checkbox: bool,
    pub pre_checked_consent: bool,
    pub cookie_banner: bool,
    pub cookie_indicators: bool,
    pub privacy_policy_link: bool,
    pub opt_out_link: bool,
    pub gpc_signal_reference: bool,
    pub privacy_contact: bool,
    pub retention_reference: bool,
    pub ai_system_reference: bool,
    pub ai_disclosure_reference: bool,
    pub security_contact_reference: bool,
    pub document: DocumentSurface,
    pub forms: FormSurface,
    pub links: LinkSurface,
    pub scripts: ScriptSurface,
    pub analytics: Vec<AnalyticsProvider>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct DocumentSurface {
    pub title_present: bool,
    pub html_lang: Option<String>,
    pub viewport_meta: bool,
    pub robots_noindex: bool,
    pub canonical_link: bool,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct FormSurface {
    pub total_forms: usize,
    pub email_inputs: usize,
    pub password_inputs: usize,
    pub telephone_inputs: usize,
    pub text_inputs: usize,
    pub textarea_inputs: usize,
    pub file_inputs: usize,
    pub hidden_inputs: usize,
    pub credit_card_inputs: usize,
    pub date_inputs: usize,
    pub insecure_actions: usize,
}

impl FormSurface {
    pub fn collects_personal_data(&self) -> bool {
        self.email_inputs > 0
            || self.password_inputs > 0
            || self.telephone_inputs > 0
            || self.text_inputs > 0
            || self.textarea_inputs > 0
            || self.file_inputs > 0
            || self.credit_card_inputs > 0
            || self.date_inputs > 0
    }

    pub fn may_collect_sensitive_data(&self) -> bool {
        self.password_inputs > 0 || self.file_inputs > 0 || self.credit_card_inputs > 0
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ScriptSurface {
    pub external_scripts: usize,
    pub tracking_pixels: usize,
    pub tag_managers: usize,
    pub consent_management_platforms: usize,
    pub captcha_providers: usize,
    pub payment_providers: usize,
    pub mixed_content_refs: usize,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct LinkSurface {
    pub total_links: usize,
    pub external_links: usize,
    pub insecure_links: usize,
    pub mailto_links: usize,
    pub terms_links: usize,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalyticsProvider {
    GoogleAnalytics,
    YandexMetrika,
    Matomo,
    Plausible,
    Amplitude,
    Segment,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingSeverity {
    Info,
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub code: &'static str,
    pub severity: FindingSeverity,
    pub title: &'static str,
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RiskAssessment {
    pub score: u8,
    pub level: RiskLevel,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Error)]
pub enum AnalyzeError {
    #[error("internal selector failed to compile: {selector}")]
    InvalidSelector { selector: &'static str },
}

pub fn analyze(scan: &ScanResult) -> Result<AnalysisReport, AnalyzeError> {
    let document = Html::parse_document(&scan.html);
    let features = detect_features(&document, &scan.html)?;
    let findings = build_findings(&features, scan);
    let risk = assess_risk(&features, scan);

    Ok(AnalysisReport {
        target: TargetMetadata {
            requested_url: scan.url.as_str().to_owned(),
            final_url: scan.final_url.as_str().to_owned(),
            status: scan.status,
            content_type: scan.content_type.clone(),
            elapsed_ms: scan.elapsed_ms,
            response_bytes: scan.response_bytes,
            security_headers: scan.security_headers.clone(),
        },
        features,
        findings,
        risk,
    })
}

fn detect_features(document: &Html, html: &str) -> Result<DetectedFeatures, AnalyzeError> {
    let consent_checkbox = has_selector_match(document, "input[type=\"checkbox\"]")?;
    let pre_checked_consent = has_selector_match(document, "input[type=\"checkbox\"][checked]")?;
    let cookie_banner = has_selector_match(
        document,
        "[id*=\"cookie\"], [class*=\"cookie\"], [aria-label*=\"cookie\"], [id*=\"consent\"], [class*=\"consent\"]",
    )?;
    let privacy_policy_link = has_selector_match(
        document,
        "a[href*=\"privacy\"], a[href*=\"policy\"], a[href*=\"privacy-policy\"], a[href*=\"персональ\"], a[href*=\"конфиденциаль\"]",
    )?;
    let opt_out_link = has_selector_match(
        document,
        "a[href*=\"do-not-sell\"], a[href*=\"do-not-share\"], a[href*=\"opt-out\"], a[href*=\"privacychoices\"], a[href*=\"privacy-options\"]",
    )?;

    let normalized = html.to_ascii_lowercase();
    let gpc_signal_reference = contains_any(
        &normalized,
        &["global privacy control", "sec-gpc", "globalprivacycontrol"],
    );
    let privacy_contact = contains_any(
        &normalized,
        &[
            "privacy@",
            "dpo@",
            "data protection officer",
            "ответственный за обработку",
        ],
    );
    let retention_reference = contains_any(
        &normalized,
        &[
            "retention",
            "data retention",
            "storage period",
            "срок хранения",
            "сроки хранения",
        ],
    );
    let ai_system_reference = contains_any(
        &normalized,
        &[
            "artificial intelligence",
            "ai system",
            "machine learning",
            "automated decision",
            "искусственный интеллект",
            "автоматизированное решение",
        ],
    );
    let ai_disclosure_reference = contains_any(
        &normalized,
        &[
            "ai-generated",
            "generated by ai",
            "automated decision-making notice",
            "обработка с использованием искусственного интеллекта",
        ],
    );
    let security_contact_reference = contains_any(
        &normalized,
        &[
            "security@",
            "vulnerability disclosure",
            "responsible disclosure",
            "incident response",
            "сообщить об уязвимости",
        ],
    );
    let cookie_indicators = contains_any(
        &normalized,
        &[
            "cookie",
            "cookies",
            "localstorage",
            "sessionstorage",
            "document.cookie",
        ],
    );

    let mut analytics = Vec::with_capacity(2);
    if contains_any(
        &normalized,
        &[
            "google-analytics.com",
            "googletagmanager.com/gtag/js",
            "googletagmanager.com/gtm.js",
            "gtag(",
            "ga(",
            "google analytics",
        ],
    ) {
        analytics.push(AnalyticsProvider::GoogleAnalytics);
    }

    if contains_any(
        &normalized,
        &[
            "mc.yandex.ru/metrika",
            "yandex.metrika",
            "ym(",
            "yandex metrika",
        ],
    ) {
        analytics.push(AnalyticsProvider::YandexMetrika);
    }

    if contains_any(
        &normalized,
        &["matomo.js", "piwik.js", "matomo.php", "piwik.php"],
    ) {
        analytics.push(AnalyticsProvider::Matomo);
    }

    if contains_any(&normalized, &["plausible.io/js", "plausible-tracker"]) {
        analytics.push(AnalyticsProvider::Plausible);
    }

    if contains_any(&normalized, &["amplitude.com", "amplitude.getinstance"]) {
        analytics.push(AnalyticsProvider::Amplitude);
    }

    if contains_any(
        &normalized,
        &["segment.com/analytics.js", "analytics.load("],
    ) {
        analytics.push(AnalyticsProvider::Segment);
    }

    Ok(DetectedFeatures {
        consent_checkbox,
        pre_checked_consent,
        cookie_banner,
        cookie_indicators,
        privacy_policy_link,
        opt_out_link,
        gpc_signal_reference,
        privacy_contact,
        retention_reference,
        ai_system_reference,
        ai_disclosure_reference,
        security_contact_reference,
        document: detect_document(document)?,
        forms: detect_forms(document)?,
        links: detect_links(document)?,
        scripts: detect_scripts(document, &normalized)?,
        analytics,
    })
}

fn has_selector_match(document: &Html, selector: &'static str) -> Result<bool, AnalyzeError> {
    let selector =
        Selector::parse(selector).map_err(|_| AnalyzeError::InvalidSelector { selector })?;
    Ok(document.select(&selector).next().is_some())
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| haystack.contains(needle))
}

fn detect_forms(document: &Html) -> Result<FormSurface, AnalyzeError> {
    let forms_selector = selector("form")?;
    let input_selector = selector("input")?;
    let textarea_selector = selector("textarea")?;

    let total_forms = document.select(&forms_selector).count();
    let mut surface = FormSurface {
        total_forms,
        ..FormSurface::default()
    };

    for input in document.select(&input_selector) {
        match input
            .value()
            .attr("type")
            .unwrap_or("text")
            .to_ascii_lowercase()
            .as_str()
        {
            "email" => surface.email_inputs += 1,
            "password" => surface.password_inputs += 1,
            "tel" | "phone" => surface.telephone_inputs += 1,
            "text" | "search" | "" => surface.text_inputs += 1,
            "file" => surface.file_inputs += 1,
            "hidden" => surface.hidden_inputs += 1,
            "date" | "datetime-local" => surface.date_inputs += 1,
            "cc-number" => surface.credit_card_inputs += 1,
            _ => {}
        }

        let autocomplete = input
            .value()
            .attr("autocomplete")
            .unwrap_or_default()
            .to_ascii_lowercase();
        if matches!(
            autocomplete.as_str(),
            "cc-number" | "cc-csc" | "cc-exp" | "cc-exp-month" | "cc-exp-year"
        ) {
            surface.credit_card_inputs += 1;
        }
    }

    surface.textarea_inputs = document.select(&textarea_selector).count();

    for form in document.select(&forms_selector) {
        if form
            .value()
            .attr("action")
            .is_some_and(|action| action.trim_start().starts_with("http://"))
        {
            surface.insecure_actions += 1;
        }
    }

    Ok(surface)
}

fn detect_scripts(document: &Html, normalized_html: &str) -> Result<ScriptSurface, AnalyzeError> {
    let script_selector = selector("script[src]")?;
    let external_scripts = document.select(&script_selector).count();
    let tracking_pixels = count_occurrences(
        normalized_html,
        &[
            "facebook.com/tr",
            "connect.facebook.net",
            "vk.com/rtrg",
            "top-fwz1.mail.ru",
            "pixel",
        ],
    );
    let tag_managers = count_occurrences(
        normalized_html,
        &["googletagmanager.com/gtm.js", "tagmanager", "tag manager"],
    );
    let consent_management_platforms = count_occurrences(
        normalized_html,
        &[
            "onetrust",
            "cookiebot",
            "usercentrics",
            "consentmanager",
            "didomi",
            "quantcast choice",
        ],
    );
    let captcha_providers = count_occurrences(
        normalized_html,
        &["google.com/recaptcha", "hcaptcha.com", "smartcaptcha"],
    );
    let payment_providers = count_occurrences(
        normalized_html,
        &[
            "js.stripe.com",
            "paypal.com/sdk/js",
            "yookassa",
            "cloudpayments",
        ],
    );
    let mixed_content_refs =
        count_occurrences(normalized_html, &["src=\"http://", "href=\"http://"]);

    Ok(ScriptSurface {
        external_scripts,
        tracking_pixels,
        tag_managers,
        consent_management_platforms,
        captcha_providers,
        payment_providers,
        mixed_content_refs,
    })
}

fn detect_document(document: &Html) -> Result<DocumentSurface, AnalyzeError> {
    let title_selector = selector("title")?;
    let html_selector = selector("html")?;
    let viewport_selector = selector("meta[name=\"viewport\"]")?;
    let robots_selector = selector("meta[name=\"robots\"]")?;
    let canonical_selector = selector("link[rel=\"canonical\"]")?;

    let html_lang = document
        .select(&html_selector)
        .next()
        .and_then(|element| element.value().attr("lang"))
        .map(str::to_owned);
    let robots_noindex = document.select(&robots_selector).any(|element| {
        element
            .value()
            .attr("content")
            .is_some_and(|content| content.to_ascii_lowercase().contains("noindex"))
    });

    Ok(DocumentSurface {
        title_present: document.select(&title_selector).next().is_some(),
        html_lang,
        viewport_meta: document.select(&viewport_selector).next().is_some(),
        robots_noindex,
        canonical_link: document.select(&canonical_selector).next().is_some(),
    })
}

fn detect_links(document: &Html) -> Result<LinkSurface, AnalyzeError> {
    let link_selector = selector("a[href]")?;
    let mut surface = LinkSurface::default();

    for link in document.select(&link_selector) {
        let Some(href) = link.value().attr("href") else {
            continue;
        };
        let normalized = href.trim().to_ascii_lowercase();
        surface.total_links += 1;

        if normalized.starts_with("http://") || normalized.starts_with("https://") {
            surface.external_links += 1;
        }

        if normalized.starts_with("http://") {
            surface.insecure_links += 1;
        }

        if normalized.starts_with("mailto:") {
            surface.mailto_links += 1;
        }

        if normalized.contains("terms")
            || normalized.contains("услов")
            || normalized.contains("terms-of-service")
        {
            surface.terms_links += 1;
        }
    }

    Ok(surface)
}

fn selector(selector: &'static str) -> Result<Selector, AnalyzeError> {
    Selector::parse(selector).map_err(|_| AnalyzeError::InvalidSelector { selector })
}

fn count_occurrences(haystack: &str, needles: &[&str]) -> usize {
    needles
        .iter()
        .filter(|needle| haystack.contains(**needle))
        .count()
}

fn build_findings(features: &DetectedFeatures, scan: &ScanResult) -> Vec<Finding> {
    let mut findings = Vec::new();

    if !features.analytics.is_empty() && !features.consent_checkbox {
        findings.push(Finding {
            code: "analytics_without_explicit_consent_control",
            severity: FindingSeverity::High,
            title: "Analytics detected without an explicit consent checkbox",
            evidence: format!(
                "Detected analytics providers: {}",
                format_providers(&features.analytics)
            ),
        });
    }

    if features.cookie_indicators && !features.cookie_banner {
        findings.push(Finding {
            code: "cookie_signals_without_visible_notice",
            severity: FindingSeverity::Medium,
            title: "Cookie-related indicators detected without a visible cookie notice",
            evidence: "HTML contains cookie/storage indicators but no cookie/consent banner selector matched.".to_owned(),
        });
    }

    if features.pre_checked_consent {
        findings.push(Finding {
            code: "pre_checked_consent_control",
            severity: FindingSeverity::High,
            title: "Consent checkbox appears to be pre-checked",
            evidence: "Detected input[type=\"checkbox\"][checked]. Consent controls should require an affirmative user action.".to_owned(),
        });
    }

    if features.forms.collects_personal_data() && !features.privacy_policy_link {
        findings.push(Finding {
            code: "forms_without_privacy_policy_link",
            severity: FindingSeverity::High,
            title: "Personal-data form inputs detected without a visible privacy policy link",
            evidence: format!(
                "Forms: {}, email inputs: {}, password inputs: {}, telephone inputs: {}, text inputs: {}, textarea inputs: {}, file inputs: {}",
                features.forms.total_forms,
                features.forms.email_inputs,
                features.forms.password_inputs,
                features.forms.telephone_inputs,
                features.forms.text_inputs,
                features.forms.textarea_inputs,
                features.forms.file_inputs
            ),
        });
    }

    if features.forms.insecure_actions > 0 {
        findings.push(Finding {
            code: "insecure_form_action",
            severity: FindingSeverity::High,
            title: "Form submits to an insecure HTTP endpoint",
            evidence: format!(
                "{} form action(s) use http:// endpoints.",
                features.forms.insecure_actions
            ),
        });
    }

    if !features.analytics.is_empty() && features.cookie_indicators {
        findings.push(Finding {
            code: "third_party_tracking_cookie_surface",
            severity: FindingSeverity::Low,
            title: "Third-party tracking and cookie surface both present",
            evidence: "Analytics scripts and cookie-related text or script usage were detected in the same document.".to_owned(),
        });
    }

    if features.scripts.tracking_pixels > 0 && !features.consent_checkbox {
        findings.push(Finding {
            code: "tracking_pixels_without_consent_control",
            severity: FindingSeverity::Medium,
            title: "Tracking pixel indicators detected without an explicit consent checkbox",
            evidence: format!(
                "{} tracking pixel indicator(s) matched in the fetched HTML.",
                features.scripts.tracking_pixels
            ),
        });
    }

    let missing_security_headers = missing_security_headers(scan);
    if missing_security_headers >= 3 {
        findings.push(Finding {
            code: "weak_security_header_posture",
            severity: FindingSeverity::Medium,
            title: "Multiple security headers are missing",
            evidence: format!(
                "{} recommended security header(s) are absent from the response.",
                missing_security_headers
            ),
        });
    }

    if features.scripts.mixed_content_refs > 0 || features.links.insecure_links > 0 {
        findings.push(Finding {
            code: "mixed_content_or_insecure_links",
            severity: FindingSeverity::Medium,
            title: "HTTP resources or links detected on the page",
            evidence: format!(
                "Mixed-content refs: {}; insecure links: {}.",
                features.scripts.mixed_content_refs, features.links.insecure_links
            ),
        });
    }

    if features.document.html_lang.is_none() {
        findings.push(Finding {
            code: "missing_document_language",
            severity: FindingSeverity::Low,
            title: "Document language is not declared",
            evidence: "The root <html> element has no lang attribute.".to_owned(),
        });
    }

    if findings.is_empty() {
        findings.push(Finding {
            code: "no_material_mvp_findings",
            severity: FindingSeverity::Info,
            title: "No material MVP compliance findings detected",
            evidence: "The current analyzer did not detect analytics/consent mismatches or missing cookie notice signals.".to_owned(),
        });
    }

    findings
}

fn assess_risk(features: &DetectedFeatures, scan: &ScanResult) -> RiskAssessment {
    let mut score = 0u16;

    if !features.analytics.is_empty() && !features.consent_checkbox {
        score += RISK_ANALYTICS_WITHOUT_CONSENT;
    }

    if features.cookie_indicators && !features.cookie_banner {
        score += RISK_MISSING_COOKIE_NOTICE;
    }

    if !features.analytics.is_empty() && features.cookie_indicators {
        score += RISK_TRACKING_WITH_COOKIE_SIGNALS;
    }

    if features.pre_checked_consent {
        score += RISK_PRECHECKED_CONSENT;
    }

    if features.forms.collects_personal_data() && !features.privacy_policy_link {
        score += RISK_FORMS_WITHOUT_POLICY;
    }

    if features.forms.insecure_actions > 0 {
        score += RISK_INSECURE_FORM_ACTION;
    }

    if missing_security_headers(scan) >= 3 {
        score += RISK_MISSING_SECURITY_HEADERS;
    }

    if features.scripts.mixed_content_refs > 0 || features.links.insecure_links > 0 {
        score += RISK_MIXED_CONTENT;
    }

    if features.document.html_lang.is_none() {
        score += RISK_MISSING_DOCUMENT_LANGUAGE;
    }

    let score = score.min(MAX_RISK_SCORE) as u8;
    let level = match score {
        0..=24 => RiskLevel::Low,
        25..=49 => RiskLevel::Medium,
        50..=74 => RiskLevel::High,
        _ => RiskLevel::Critical,
    };

    RiskAssessment { score, level }
}

fn missing_security_headers(scan: &ScanResult) -> usize {
    [
        scan.security_headers.content_security_policy,
        scan.security_headers.strict_transport_security,
        scan.security_headers.x_frame_options,
        scan.security_headers.referrer_policy,
        scan.security_headers.permissions_policy,
    ]
    .into_iter()
    .filter(|present| !present)
    .count()
}

pub fn format_providers(providers: &[AnalyticsProvider]) -> String {
    providers
        .iter()
        .map(|provider| match provider {
            AnalyticsProvider::GoogleAnalytics => "Google Analytics",
            AnalyticsProvider::YandexMetrika => "Yandex Metrika",
            AnalyticsProvider::Matomo => "Matomo",
            AnalyticsProvider::Plausible => "Plausible",
            AnalyticsProvider::Amplitude => "Amplitude",
            AnalyticsProvider::Segment => "Segment",
        })
        .collect::<Vec<_>>()
        .join(", ")
}
