use anyhow::Result;
use colored::{ColoredString, Colorize};
use serde::Serialize;

use crate::analyzer::{AnalysisReport, FindingSeverity, RiskLevel, format_providers};
use crate::ui::UiText;
use crate::{locale::Locale, rules::RuleEvaluation};

pub fn print_human(report: &AnalysisReport, locale: Locale, legal: &[RuleEvaluation], ui: &UiText) {
    println!("{}", ui.text("scan.title").bold());
    println!("{}: {}", ui.text("label.target"), report.target.final_url);
    println!("{}: {}", ui.text("label.http_status"), report.target.status);
    println!(
        "{}: {} ({})",
        ui.text("label.legal_locale"),
        locale,
        locale.legal_framework()
    );
    println!("{}: {}", ui.text("label.ui_locale"), ui.locale().code());
    println!(
        "{}: {} bytes in {} ms",
        ui.text("label.response"),
        report.target.response_bytes,
        report.target.elapsed_ms
    );

    if let Some(content_type) = &report.target.content_type {
        println!("{}: {content_type}", ui.text("label.content_type"));
    }

    println!();
    println!("{}", ui.text("section.detected_features").bold());
    println!(
        "{}: {}",
        ui.text("label.consent_checkbox"),
        status_label(report.features.consent_checkbox, ui)
    );
    println!(
        "{}: {}",
        ui.text("label.prechecked_consent"),
        status_label(report.features.pre_checked_consent, ui)
    );
    println!(
        "{}: {}",
        ui.text("label.cookie_banner"),
        status_label(report.features.cookie_banner, ui)
    );
    println!(
        "{}: {}",
        ui.text("label.cookie_indicators"),
        status_label(report.features.cookie_indicators, ui)
    );
    println!(
        "{}: {}",
        ui.text("label.privacy_policy_link"),
        status_label(report.features.privacy_policy_link, ui)
    );
    println!(
        "Opt-out link: {}, GPC reference: {}",
        status_label(report.features.opt_out_link, ui),
        status_label(report.features.gpc_signal_reference, ui)
    );
    println!(
        "{}: {} total, {} personal-data input(s), {} hidden input(s), {} insecure action(s)",
        ui.text("label.forms"),
        report.features.forms.total_forms,
        report.features.forms.email_inputs
            + report.features.forms.password_inputs
            + report.features.forms.telephone_inputs
            + report.features.forms.text_inputs
            + report.features.forms.textarea_inputs
            + report.features.forms.file_inputs,
        report.features.forms.hidden_inputs,
        report.features.forms.insecure_actions
    );
    println!(
        "{}: {} external, {} tracking pixel indicator(s), {} tag-manager indicator(s), {} CMP indicator(s), {} captcha provider(s), {} payment provider(s), {} mixed-content ref(s)",
        ui.text("label.scripts"),
        report.features.scripts.external_scripts,
        report.features.scripts.tracking_pixels,
        report.features.scripts.tag_managers,
        report.features.scripts.consent_management_platforms,
        report.features.scripts.captcha_providers,
        report.features.scripts.payment_providers,
        report.features.scripts.mixed_content_refs
    );
    println!(
        "{}: {} {}, {} {}, {} {}, {} {}, {} {}",
        ui.text("label.document"),
        ui.text("label.title"),
        status_label(report.features.document.title_present, ui),
        ui.text("label.lang"),
        report
            .features
            .document
            .html_lang
            .as_deref()
            .unwrap_or(ui.text("status.no")),
        ui.text("label.viewport"),
        status_label(report.features.document.viewport_meta, ui),
        ui.text("label.canonical"),
        status_label(report.features.document.canonical_link, ui),
        ui.text("label.noindex"),
        status_label(report.features.document.robots_noindex, ui)
    );
    println!(
        "{}: {} {}, {} {}, {} {}, {} mailto, {} {}",
        ui.text("label.links"),
        report.features.links.total_links,
        ui.text("label.total"),
        report.features.links.external_links,
        ui.text("label.external"),
        report.features.links.insecure_links,
        ui.text("label.insecure"),
        report.features.links.mailto_links,
        report.features.links.terms_links,
        ui.text("label.terms")
    );
    println!(
        "{}: {}",
        ui.text("label.analytics"),
        if report.features.analytics.is_empty() {
            ui.none().normal()
        } else {
            format_providers(&report.features.analytics).cyan()
        }
    );

    println!();
    println!("{}", ui.text("section.security").bold());
    println!(
        "CSP: {}, HSTS: {}, X-Frame-Options: {}, Referrer-Policy: {}, Permissions-Policy: {}",
        status_label(report.target.security_headers.content_security_policy, ui),
        status_label(report.target.security_headers.strict_transport_security, ui),
        status_label(report.target.security_headers.x_frame_options, ui),
        status_label(report.target.security_headers.referrer_policy, ui),
        status_label(report.target.security_headers.permissions_policy, ui)
    );

    println!();
    println!(
        "{} {} ({}/100)",
        format!("{}:", ui.text("label.risk")).bold(),
        risk_label(&report.risk.level, ui),
        report.risk.score
    );

    println!();
    println!("{}", ui.text("section.findings").bold());
    for finding in &report.findings {
        println!(
            "- {} {}",
            severity_label(&finding.severity, ui),
            ui.finding_title(finding).bold()
        );
        println!("  {}: {}", ui.text("label.code"), finding.code);
        println!("  {}: {}", ui.text("label.evidence"), finding.evidence);
    }

    println!();
    println!("{}", ui.text("section.legal").bold());
    let applicable = legal
        .iter()
        .filter(|evaluation| evaluation.applies)
        .collect::<Vec<_>>();
    if applicable.is_empty() {
        println!("{}", ui.text("message.no_applicable_rules"));
    }
    for evaluation in applicable {
        println!(
            "- {} {} {}: {}",
            evaluation.rule_id.cyan(),
            ui.text("label.severity"),
            evaluation.severity,
            evaluation.requirement
        );
    }
}

pub fn print_json(report: &AnalysisReport, locale: Locale, legal: &[RuleEvaluation]) -> Result<()> {
    let payload = JsonReport {
        locale,
        analysis: report,
        legal,
    };
    let json = serde_json::to_string_pretty(&payload)?;
    println!("{json}");
    Ok(())
}

#[derive(Serialize)]
struct JsonReport<'a> {
    locale: Locale,
    analysis: &'a AnalysisReport,
    legal: &'a [RuleEvaluation],
}

fn status_label(value: bool, ui: &UiText) -> ColoredString {
    if value {
        ui.status(true).green()
    } else {
        ui.status(false).yellow()
    }
}

fn severity_label(severity: &FindingSeverity, ui: &UiText) -> ColoredString {
    match severity {
        FindingSeverity::Info => ui.severity(severity).blue(),
        FindingSeverity::Low => ui.severity(severity).cyan(),
        FindingSeverity::Medium => ui.severity(severity).yellow(),
        FindingSeverity::High => ui.severity(severity).red().bold(),
    }
}

fn risk_label(level: &RiskLevel, ui: &UiText) -> ColoredString {
    match level {
        RiskLevel::Low => ui.risk(level).green(),
        RiskLevel::Medium => ui.risk(level).yellow(),
        RiskLevel::High => ui.risk(level).red(),
        RiskLevel::Critical => ui.risk(level).red().bold(),
    }
}
