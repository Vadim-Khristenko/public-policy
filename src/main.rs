mod analyzer;
mod cli;
mod documents;
mod generator;
mod guide;
mod locale;
mod policy;
mod report;
mod rules;
mod scanner;
mod schema;
mod templates;
mod tui;
mod ui;

use anyhow::Result;
use clap::Parser;
use colored::Colorize;
use std::time::Duration;

use crate::cli::{Cli, Command, OutputMode};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let ui = ui::UiText::load(cli.ui_locale, cli.ui_locale_file.as_deref())?;

    match cli.command.normalize() {
        Command::Scan {
            url,
            output,
            locale,
            rules: rules_path,
            timeout_seconds,
            max_bytes,
            ..
        } => {
            let custom_rules = rules::load_optional_rules(rules_path.as_deref())?;
            let scan_config = scanner::ScanConfig {
                timeout: Duration::from_secs(timeout_seconds),
                max_response_bytes: max_bytes,
            };
            let scanned = scanner::scan_url_with_config(&url, &scan_config).await?;
            let analysis = analyzer::analyze(&scanned)?;
            let legal = rules::evaluate_rules(&analysis.features, locale, None, &custom_rules);

            match output {
                OutputMode::Human => report::print_human(&analysis, locale, &legal, &ui),
                OutputMode::Json => report::print_json(&analysis, locale, &legal)?,
            }
        }
        Command::GeneratePolicy {
            from_url,
            schema,
            locale,
            document,
            rules: rules_path,
            timeout_seconds,
            max_bytes,
            company_name,
        } => {
            let policy_schema = schema::load_optional_schema(schema.as_deref())?;
            let custom_rules = rules::load_optional_rules(rules_path.as_deref())?;
            let analysis = match from_url {
                Some(url) => {
                    let scan_config = scanner::ScanConfig {
                        timeout: Duration::from_secs(timeout_seconds),
                        max_response_bytes: max_bytes,
                    };
                    let scanned = scanner::scan_url_with_config(&url, &scan_config).await?;
                    Some(analyzer::analyze(&scanned)?)
                }
                None => None,
            };
            let markdown = policy::generate_policy(generator::PolicyGenerationRequest {
                document_type: document,
                locale,
                analysis: analysis.as_ref(),
                schema: policy_schema.as_ref(),
                custom_rules: &custom_rules,
                company_name: &company_name,
            })?;
            println!("{markdown}");
        }
        Command::ValidateRules { rules } => {
            let loaded = rules::load_rules(&rules)?;
            rules::validate_rules(&loaded)?;
            println!(
                "{}: {} rule(s)",
                ui.text("message.rules_valid").green().bold(),
                loaded.len().to_string().cyan()
            );
        }
        Command::Guide => guide::print(&ui),
        Command::Tui {
            url,
            locale,
            rules: rules_path,
            timeout_seconds,
            max_bytes,
        } => {
            let custom_rules = rules::load_optional_rules(rules_path.as_deref())?;
            tui::run(tui::TuiRequest {
                url: url.as_ref(),
                legal_locale: locale,
                ui: &ui,
                scan_config: scanner::ScanConfig {
                    timeout: Duration::from_secs(timeout_seconds),
                    max_response_bytes: max_bytes,
                },
                custom_rules: &custom_rules,
            })
            .await?;
        }
    }

    Ok(())
}
