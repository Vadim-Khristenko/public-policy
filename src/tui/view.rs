use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Tabs, Wrap},
};

use crate::{analyzer::AnalysisReport, locale::Locale, rules::RuleEvaluation, ui::UiText};

pub fn render_home(frame: &mut Frame<'_>, command: &str, message: &str, ui: &UiText) {
    let area = frame.area();
    let panel = Paragraph::new(vec![
        Line::from(Span::styled(
            "AVRORA",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from("Interactive shell mode. Commands execute inside this TUI."),
        Line::from("Commands: help | scan <url> | clear | q"),
        Line::from("Scan view: 1-4 switch tabs, h returns home."),
        Line::from(""),
        Line::from(format!("status: {message}")),
        Line::from(format!("avrora> {command}")),
    ])
    .block(
        Block::default()
            .title(ui.text("scan.title"))
            .borders(Borders::ALL),
    )
    .wrap(Wrap { trim: true });

    frame.render_widget(panel, area);
}

pub fn render_scan(
    frame: &mut Frame<'_>,
    analysis: &AnalysisReport,
    legal: &[RuleEvaluation],
    legal_locale: Locale,
    tab: usize,
    ui: &UiText,
) {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(3),
        ])
        .split(frame.area());

    frame.render_widget(summary_panel(analysis, legal_locale, ui), vertical[0]);
    frame.render_widget(tabs(tab), vertical[1]);

    match tab {
        0 => frame.render_widget(summary_detail_panel(analysis, ui), vertical[2]),
        1 => frame.render_widget(features_panel(analysis, ui), vertical[2]),
        2 => frame.render_widget(findings_panel(analysis, ui), vertical[2]),
        _ => frame.render_widget(legal_panel(legal, ui), vertical[2]),
    }

    frame.render_widget(footer(), vertical[3]);
}

fn tabs<'a>(tab: usize) -> Tabs<'a> {
    Tabs::new(vec!["1 Summary", "2 Features", "3 Findings", "4 Legal"])
        .select(tab)
        .block(Block::default().borders(Borders::ALL))
        .style(Style::default().fg(Color::Gray))
        .highlight_style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
}

fn summary_panel<'a>(
    analysis: &'a AnalysisReport,
    legal_locale: Locale,
    ui: &'a UiText,
) -> Paragraph<'a> {
    let risk_style = risk_style(analysis.risk.score);
    Paragraph::new(vec![
        Line::from(vec![
            Span::styled("AVRORA ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(analysis.target.final_url.as_str()),
        ]),
        Line::from(format!(
            "{}: {} | {}: {} ({}) | {}: {} bytes / {} ms",
            ui.text("label.http_status"),
            analysis.target.status,
            ui.text("label.legal_locale"),
            legal_locale,
            legal_locale.legal_framework(),
            ui.text("label.response"),
            analysis.target.response_bytes,
            analysis.target.elapsed_ms
        )),
        Line::from(vec![
            Span::raw(format!("{}: ", ui.text("label.risk"))),
            Span::styled(format!("{}/100", analysis.risk.score), risk_style),
        ]),
    ])
    .block(
        Block::default()
            .title(ui.text("scan.title"))
            .borders(Borders::ALL),
    )
}

fn summary_detail_panel<'a>(analysis: &'a AnalysisReport, ui: &'a UiText) -> Paragraph<'a> {
    Paragraph::new(vec![
        Line::from(format!(
            "{}: {}",
            ui.text("label.target"),
            analysis.target.final_url
        )),
        Line::from(format!(
            "{}: {}",
            ui.text("label.content_type"),
            analysis.target.content_type.as_deref().unwrap_or(ui.none())
        )),
        Line::from(format!(
            "CSP: {} | HSTS: {} | XFO: {} | Referrer: {} | Permissions: {}",
            ui.status(analysis.target.security_headers.content_security_policy),
            ui.status(analysis.target.security_headers.strict_transport_security),
            ui.status(analysis.target.security_headers.x_frame_options),
            ui.status(analysis.target.security_headers.referrer_policy),
            ui.status(analysis.target.security_headers.permissions_policy)
        )),
    ])
    .block(Block::default().title("Summary").borders(Borders::ALL))
}

fn features_panel<'a>(analysis: &'a AnalysisReport, ui: &'a UiText) -> Paragraph<'a> {
    Paragraph::new(vec![
        Line::from(format!(
            "{}: {} | {}: {} | {}: {} | opt-out: {} | GPC: {}",
            ui.text("label.consent_checkbox"),
            ui.status(analysis.features.consent_checkbox),
            ui.text("label.cookie_indicators"),
            ui.status(analysis.features.cookie_indicators),
            ui.text("label.privacy_policy_link"),
            ui.status(analysis.features.privacy_policy_link),
            ui.status(analysis.features.opt_out_link),
            ui.status(analysis.features.gpc_signal_reference),
        )),
        Line::from(format!(
            "{}: {} forms, {} email, {} password, {} file, {} sensitive, {} insecure actions",
            ui.text("label.forms"),
            analysis.features.forms.total_forms,
            analysis.features.forms.email_inputs,
            analysis.features.forms.password_inputs,
            analysis.features.forms.file_inputs,
            ui.status(analysis.features.forms.may_collect_sensitive_data()),
            analysis.features.forms.insecure_actions
        )),
        Line::from(format!(
            "{}: {} external, {} pixels, {} tag managers, {} CMP, {} captcha, {} payment",
            ui.text("label.scripts"),
            analysis.features.scripts.external_scripts,
            analysis.features.scripts.tracking_pixels,
            analysis.features.scripts.tag_managers,
            analysis.features.scripts.consent_management_platforms,
            analysis.features.scripts.captcha_providers,
            analysis.features.scripts.payment_providers
        )),
    ])
    .block(
        Block::default()
            .title(ui.text("section.detected_features"))
            .borders(Borders::ALL),
    )
}

fn findings_panel<'a>(analysis: &'a AnalysisReport, ui: &'a UiText) -> List<'a> {
    let items = analysis
        .findings
        .iter()
        .map(|finding| {
            ListItem::new(vec![
                Line::from(Span::styled(
                    format!(
                        "{} {}",
                        ui.severity(&finding.severity),
                        ui.finding_title(finding)
                    ),
                    Style::default().fg(Color::Yellow),
                )),
                Line::from(format!("{}: {}", ui.text("label.code"), finding.code)),
                Line::from(format!(
                    "{}: {}",
                    ui.text("label.evidence"),
                    finding.evidence
                )),
            ])
        })
        .collect::<Vec<_>>();

    List::new(items).block(
        Block::default()
            .title(ui.text("section.findings"))
            .borders(Borders::ALL),
    )
}

fn legal_panel<'a>(legal: &'a [RuleEvaluation], ui: &'a UiText) -> List<'a> {
    let mut items = legal
        .iter()
        .filter(|evaluation| evaluation.applies)
        .map(|evaluation| {
            ListItem::new(vec![
                Line::from(Span::styled(
                    format!("{} ({})", evaluation.rule_id, evaluation.severity),
                    Style::default().fg(Color::Cyan),
                )),
                Line::from(evaluation.requirement.as_str()),
            ])
        })
        .collect::<Vec<_>>();

    if items.is_empty() {
        items.push(ListItem::new(ui.text("message.no_applicable_rules")));
    }

    List::new(items).block(
        Block::default()
            .title(ui.text("section.legal"))
            .borders(Borders::ALL),
    )
}

fn footer<'a>() -> Paragraph<'a> {
    Paragraph::new("1-4: switch tabs | q / Esc: quit")
        .block(Block::default().borders(Borders::ALL))
        .wrap(Wrap { trim: true })
}

fn risk_style(score: u8) -> Style {
    match score {
        0..=24 => Style::default().fg(Color::Green),
        25..=49 => Style::default().fg(Color::Yellow),
        50..=74 => Style::default().fg(Color::Red),
        _ => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
    }
}
