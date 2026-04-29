use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};
use url::Url;

use crate::documents::DocumentType;
use crate::locale::Locale;
use crate::ui::UiLocale;

#[derive(Debug, Parser)]
#[command(
    name = "avrora",
    version,
    about = "AVRORA policy-as-code compliance engine",
    propagate_version = true
)]
pub struct Cli {
    /// Language used for AVRORA's own CLI output.
    #[arg(long, global = true, value_enum, default_value_t = UiLocale::En)]
    pub ui_locale: UiLocale,

    /// Optional JSON/YAML file overriding built-in CLI output labels.
    #[arg(long, global = true)]
    pub ui_locale_file: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Scan a website and report privacy/compliance signals.
    Scan {
        /// Website URL to scan.
        url: Url,

        /// Legal locale used for law-aware rule evaluation.
        #[arg(long, value_enum, default_value_t = Locale::En)]
        locale: Locale,

        /// Optional YAML file with custom legal/compliance rules.
        #[arg(long)]
        rules: Option<PathBuf>,

        /// Request timeout in seconds.
        #[arg(long, default_value_t = 15)]
        timeout_seconds: u64,

        /// Maximum response body size to download.
        #[arg(long, default_value_t = 5 * 1024 * 1024)]
        max_bytes: u64,

        /// Emit a structured JSON report.
        #[arg(long = "json", conflicts_with = "output")]
        json: bool,

        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputMode::Human)]
        output: OutputMode,
    },

    /// Generate a baseline privacy policy in Markdown.
    GeneratePolicy {
        /// Legal locale for policy generation.
        #[arg(long, value_enum, default_value_t = Locale::En)]
        locale: Locale,

        /// Document type to generate.
        #[arg(long, value_enum, default_value_t = DocumentType::Privacy)]
        document: DocumentType,

        /// Scan a website first and generate the policy from detected behavior.
        #[arg(long)]
        from_url: Option<Url>,

        /// Optional JSON/YAML policy schema file.
        #[arg(long)]
        schema: Option<PathBuf>,

        /// Optional YAML file with custom legal/compliance rules.
        #[arg(long)]
        rules: Option<PathBuf>,

        /// Request timeout in seconds when --from-url is used.
        #[arg(long, default_value_t = 15)]
        timeout_seconds: u64,

        /// Maximum response body size when --from-url is used.
        #[arg(long, default_value_t = 5 * 1024 * 1024)]
        max_bytes: u64,

        /// Company name injected into locale-specific templates.
        #[arg(long, default_value = "the organization")]
        company_name: String,
    },

    /// Validate custom rules YAML without scanning a website.
    ValidateRules {
        /// YAML rules file to validate.
        rules: PathBuf,
    },

    /// Print localized command guide using --ui-locale and --ui-locale-file.
    Guide,

    /// Open an interactive terminal scan dashboard.
    Tui {
        /// Optional website URL to scan; without URL, AVRORA opens the TUI shell home screen.
        url: Option<Url>,

        /// Legal locale used for law-aware rule evaluation.
        #[arg(long, value_enum, default_value_t = Locale::En)]
        locale: Locale,

        /// Optional YAML file with custom legal/compliance rules.
        #[arg(long)]
        rules: Option<PathBuf>,

        /// Request timeout in seconds.
        #[arg(long, default_value_t = 15)]
        timeout_seconds: u64,

        /// Maximum response body size to download.
        #[arg(long, default_value_t = 5 * 1024 * 1024)]
        max_bytes: u64,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum OutputMode {
    Human,
    Json,
}

impl Command {
    pub fn normalize(self) -> Self {
        match self {
            Command::Scan {
                url,
                locale,
                rules,
                timeout_seconds,
                max_bytes,
                json,
                output,
            } => Command::Scan {
                url,
                locale,
                rules,
                timeout_seconds,
                max_bytes,
                json,
                output: if json { OutputMode::Json } else { output },
            },
            Command::GeneratePolicy {
                locale,
                document,
                from_url,
                schema,
                rules,
                timeout_seconds,
                max_bytes,
                company_name,
            } => Command::GeneratePolicy {
                locale,
                document,
                from_url,
                schema,
                rules,
                timeout_seconds,
                max_bytes,
                company_name,
            },
            Command::ValidateRules { rules } => Command::ValidateRules { rules },
            Command::Guide => Command::Guide,
            Command::Tui {
                url,
                locale,
                rules,
                timeout_seconds,
                max_bytes,
            } => Command::Tui {
                url,
                locale,
                rules,
                timeout_seconds,
                max_bytes,
            },
        }
    }
}
