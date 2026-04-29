use std::{io, time::Duration};

use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{Terminal, backend::CrosstermBackend};
use url::Url;

#[path = "tui/view.rs"]
mod view;

use crate::{
    analyzer::{self, AnalysisReport},
    locale::Locale,
    rules::{self, LegalRule, RuleEvaluation},
    scanner::{self, ScanConfig},
    ui::UiText,
};

pub struct TuiRequest<'a> {
    pub url: Option<&'a Url>,
    pub legal_locale: Locale,
    pub ui: &'a UiText,
    pub scan_config: ScanConfig,
    pub custom_rules: &'a [LegalRule],
}

pub async fn run(request: TuiRequest<'_>) -> Result<()> {
    let state = if let Some(url) = request.url {
        scan_state(
            url,
            request.legal_locale,
            &request.scan_config,
            request.custom_rules,
        )
        .await?
    } else {
        TuiState::Home {
            command: String::new(),
            message: "Type `help`, `scan <url>`, `clear`, or `q`.".to_owned(),
        }
    };

    render_loop(
        state,
        request.legal_locale,
        request.scan_config,
        request.custom_rules.to_vec(),
        request.ui,
    )
    .await
}

#[derive(Debug)]
enum TuiState {
    Home {
        command: String,
        message: String,
    },
    Scan {
        analysis: Box<AnalysisReport>,
        legal: Vec<RuleEvaluation>,
        legal_locale: Locale,
        tab: Tab,
    },
}

#[derive(Clone, Copy, Debug)]
enum Tab {
    Summary,
    Features,
    Findings,
    Legal,
}

async fn render_loop(
    mut state: TuiState,
    default_legal_locale: Locale,
    scan_config: ScanConfig,
    custom_rules: Vec<LegalRule>,
    ui: &UiText,
) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    let result = run_terminal(
        &mut terminal,
        &mut state,
        default_legal_locale,
        &scan_config,
        &custom_rules,
        ui,
    )
    .await;

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result
}

async fn run_terminal(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    state: &mut TuiState,
    default_legal_locale: Locale,
    scan_config: &ScanConfig,
    custom_rules: &[LegalRule],
    ui: &UiText,
) -> Result<()> {
    loop {
        terminal.draw(|frame| match state {
            TuiState::Home { command, message } => view::render_home(frame, command, message, ui),
            TuiState::Scan {
                analysis,
                legal,
                legal_locale,
                tab,
            } => view::render_scan(frame, analysis, legal, *legal_locale, *tab as usize, ui),
        })?;

        if event::poll(Duration::from_millis(250))?
            && let Event::Key(key) = event::read()?
            && handle_key(
                state,
                key.code,
                default_legal_locale,
                scan_config,
                custom_rules,
            )
            .await?
        {
            break;
        }
    }

    Ok(())
}

async fn handle_key(
    state: &mut TuiState,
    key: KeyCode,
    default_legal_locale: Locale,
    scan_config: &ScanConfig,
    custom_rules: &[LegalRule],
) -> Result<bool> {
    match state {
        TuiState::Home { command, message } => match key {
            KeyCode::Esc => return Ok(true),
            KeyCode::Enter => {
                let input = command.trim().to_owned();
                command.clear();
                execute_home_command(
                    state,
                    &input,
                    default_legal_locale,
                    scan_config,
                    custom_rules,
                )
                .await?;
            }
            KeyCode::Backspace => {
                command.pop();
            }
            KeyCode::Char('q') if command.is_empty() => return Ok(true),
            KeyCode::Char(ch) => command.push(ch),
            _ => {
                *message = "Unsupported key in command mode.".to_owned();
            }
        },
        TuiState::Scan { .. } => match key {
            KeyCode::Char('q') | KeyCode::Esc => return Ok(true),
            KeyCode::Char('h') => {
                *state = TuiState::Home {
                    command: String::new(),
                    message: "Back to shell. Type `help` or `scan <url>`.".to_owned(),
                };
            }
            KeyCode::Char('1') => set_tab(state, Tab::Summary),
            KeyCode::Char('2') => set_tab(state, Tab::Features),
            KeyCode::Char('3') => set_tab(state, Tab::Findings),
            KeyCode::Char('4') => set_tab(state, Tab::Legal),
            _ => {}
        },
    }

    Ok(false)
}

async fn execute_home_command(
    state: &mut TuiState,
    input: &str,
    default_legal_locale: Locale,
    scan_config: &ScanConfig,
    custom_rules: &[LegalRule],
) -> Result<()> {
    let mut parts = input.split_whitespace();
    let command = parts.next().unwrap_or_default();

    match command {
        "" | "help" | "guide" => {
            *state = TuiState::Home {
                command: String::new(),
                message: "Commands: scan <url>, clear, help, q. Scan view: 1-4 tabs, h home."
                    .to_owned(),
            };
        }
        "clear" => {
            *state = TuiState::Home {
                command: String::new(),
                message: "Cleared.".to_owned(),
            };
        }
        "q" | "quit" | "exit" => {}
        "scan" => {
            if let Some(raw_url) = parts.next() {
                let url = Url::parse(raw_url)?;
                *state = scan_state(&url, default_legal_locale, scan_config, custom_rules).await?;
            } else {
                *state = TuiState::Home {
                    command: String::new(),
                    message: "Usage: scan <url>".to_owned(),
                };
            }
        }
        other => {
            *state = TuiState::Home {
                command: String::new(),
                message: format!("Unknown command `{other}`. Type `help`."),
            };
        }
    }

    Ok(())
}

async fn scan_state(
    url: &Url,
    legal_locale: Locale,
    scan_config: &ScanConfig,
    custom_rules: &[LegalRule],
) -> Result<TuiState> {
    let scanned = scanner::scan_url_with_config(url, scan_config).await?;
    let analysis = analyzer::analyze(&scanned)?;
    let legal = rules::evaluate_rules(&analysis.features, legal_locale, None, custom_rules);

    Ok(TuiState::Scan {
        analysis: Box::new(analysis),
        legal,
        legal_locale,
        tab: Tab::Summary,
    })
}

fn set_tab(state: &mut TuiState, next: Tab) {
    if let TuiState::Scan { tab, .. } = state {
        *tab = next;
    }
}
