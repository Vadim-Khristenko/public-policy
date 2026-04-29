# AVRORA

AVRORA is a Rust policy-as-code compliance engine for website privacy and legal-risk analysis.

## Commands

```bash
avrora scan https://example.com
avrora scan https://example.com --locale ru --ui-locale ru
avrora scan https://example.com --json
avrora tui https://example.com --locale us-ca
avrora generate-policy --locale en
avrora generate-policy --locale ru --company-name "Example LLC"
avrora generate-policy --locale us-ca --company-name "Example Inc."
avrora generate-policy --document cookie --locale en
avrora generate-policy --document processing-notice --locale us-ca
avrora validate-rules rules.example.yaml
avrora --ui-locale ru guide
```

## Scanner Controls

```bash
avrora scan https://example.com --timeout-seconds 10 --max-bytes 5242880
```

The scanner records response size, elapsed time, content type, security headers, form surface,
link surface, document metadata, scripts, analytics, cookies, tracking pixels, CMP indicators,
captcha providers, payment providers, and mixed-content references.

Built-in analytics detection currently covers Google Analytics, Yandex Metrika, Matomo, Plausible,
Amplitude, and Segment indicators.

## TUI

```bash
avrora tui https://example.com --locale en
avrora tui https://example.com --locale ru --ui-locale ru
avrora tui https://example.com --locale us-ca
```

The TUI opens an alternate-screen dashboard with summary, detected features, findings, and legal
rule evaluation.

Without a URL, TUI starts as an interactive shell:

```text
help
scan https://example.com
clear
q
```

In scan view, use `1`-`4` to switch tabs, `h` to return home, and `q` or `Esc` to exit.

## Locales

`--locale` controls the legal framework:

- `en`: GDPR-style policy/rules
- `ru`: Russian 152-FZ policy/rules
- `us-ca`: California CCPA/CPRA policy/rules

The legal rule set also includes PECR/ePrivacy-style checks for cookies, tracking pixels, scripts,
tags, web storage, and similar storage/access technologies under the English locale.

`--ui-locale` controls AVRORA's own CLI output:

- `en`
- `ru`

Built-in UI labels can be overridden with a JSON/YAML file:

```bash
avrora --ui-locale en --ui-locale-file locales/tool.ru.yaml validate-rules rules.example.yaml
```

Locale files are flat key-value maps:

```yaml
scan.title: "AVRORA: проверка соответствия"
message.rules_valid: "Файл правил корректен"
```

## Custom Rules

```yaml
- id: custom_tracking_rule
  condition: analytics == true
  requirement: User must explicitly accept tracking before non-essential analytics starts.
  severity: 70
```

Supported conditions include:

- `analytics == true`
- `cookies == true`
- `consent == false`
- `pre_checked_consent == true`
- `privacy_policy == false`
- `forms_collect_personal_data == true`
- `storage_location != russia`
- `declared_purposes == false`
- `privacy_contact == false`
- `retention_reference == false`
- `ai_disclosure == false`
- `security_contact == false`

Rules can provide localized requirements:

```yaml
- id: custom_tracking_rule
  condition: analytics == true
  requirements:
    en: User must explicitly accept tracking before non-essential analytics starts.
    ru: Пользователь должен явно принять tracking до запуска необязательной аналитики.
    us-ca: User opt-out and applicable privacy-control choices must be honored before sale/share tracking.
  severity: 70
```

For backward compatibility, `requirement: "..."` is still accepted and treated as the English fallback.
