use colored::Colorize;

use crate::ui::{UiLocale, UiText};

pub fn print(ui: &UiText) {
    match ui.locale() {
        UiLocale::En => print_en(),
        UiLocale::Ru => print_ru(),
    }
}

fn print_en() {
    println!("{}", "AVRORA Command Guide".cyan().bold());
    println!();
    println!("{}", "Scan".bold());
    println!("  avrora scan <url> [--locale en|ru|us-ca] [--json]");
    println!("  avrora scan <url> --rules rules.yaml");
    println!();
    println!("{}", "Generate Documents".bold());
    println!("  avrora generate-policy --document privacy");
    println!("  avrora generate-policy --document cookie --locale en");
    println!("  avrora generate-policy --document processing-notice --locale us-ca");
    println!();
    println!("{}", "TUI".bold());
    println!("  avrora tui");
    println!("  avrora tui <url> --locale ru --ui-locale ru");
    println!();
    println!("{}", "Rules".bold());
    println!("  avrora validate-rules rules.example.yaml");
}

fn print_ru() {
    println!("{}", "AVRORA: справочник команд".cyan().bold());
    println!();
    println!("{}", "Сканирование".bold());
    println!("  avrora scan <url> [--locale en|ru|us-ca] [--json]");
    println!("  avrora scan <url> --rules rules.yaml");
    println!();
    println!("{}", "Генерация документов".bold());
    println!("  avrora generate-policy --document privacy");
    println!("  avrora generate-policy --document cookie --locale ru");
    println!("  avrora generate-policy --document processing-notice --locale us-ca");
    println!();
    println!("{}", "TUI-оболочка".bold());
    println!("  avrora tui");
    println!("  avrora tui <url> --locale ru --ui-locale ru");
    println!();
    println!("{}", "Правила".bold());
    println!("  avrora validate-rules rules.example.yaml");
}
