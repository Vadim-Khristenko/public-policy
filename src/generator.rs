use anyhow::Result;

use crate::{
    analyzer::{AnalysisReport, format_providers},
    documents::DocumentType,
    locale::Locale,
    rules::{self, LegalRule, RuleEvaluation},
    schema::PolicySchema,
    templates::{Template, TemplateVariables},
};

pub struct PolicyGenerationRequest<'a> {
    pub document_type: DocumentType,
    pub locale: Locale,
    pub analysis: Option<&'a AnalysisReport>,
    pub schema: Option<&'a PolicySchema>,
    pub custom_rules: &'a [LegalRule],
    pub company_name: &'a str,
}

pub fn generate_policy(request: PolicyGenerationRequest<'_>) -> Result<String> {
    let template = Template::document(request.locale, request.document_type);
    let legal = request
        .analysis
        .map(|analysis| {
            rules::evaluate_rules(
                &analysis.features,
                request.locale,
                request.schema,
                request.custom_rules,
            )
        })
        .unwrap_or_else(|| {
            rules::builtin_rules(request.locale)
                .into_iter()
                .chain(request.custom_rules.iter().cloned())
                .map(|rule| RuleEvaluation {
                    rule_id: rule.id,
                    applies: true,
                    requirement: rule.requirement.resolve(request.locale),
                    severity: rule.severity,
                })
                .collect()
        });

    let mut variables = TemplateVariables::default();
    variables.insert(
        "company_name",
        request
            .schema
            .and_then(|schema| schema.company_name.as_deref())
            .unwrap_or(request.company_name),
    );
    variables.insert(
        "data_types",
        render_data_types(request.schema, request.locale),
    );
    variables.insert("purposes", render_purposes(request.schema, request.locale));
    variables.insert(
        "analytics",
        render_analytics(request.analysis, request.locale),
    );
    variables.insert("cookies", render_cookies(request.analysis, request.locale));
    variables.insert("forms", render_forms(request.analysis, request.locale));
    variables.insert(
        "third_parties",
        render_third_parties(request.schema, request.analysis, request.locale),
    );
    variables.insert(
        "storage_location",
        request
            .schema
            .and_then(|schema| schema.storage_location.as_deref())
            .unwrap_or(match request.locale {
                Locale::En | Locale::UsCa => "not declared",
                Locale::Ru => "не указано",
            }),
    );
    variables.insert(
        "legal_requirements",
        render_legal_requirements(&legal, request.locale),
    );

    template.render(&variables)
}

fn render_data_types(schema: Option<&PolicySchema>, locale: Locale) -> String {
    if let Some(schema) = schema.filter(|schema| !schema.data_types.is_empty()) {
        return schema
            .data_types
            .iter()
            .map(|data_type| {
                let mut line = format!("- {}", data_type.name);
                if let Some(category) = &data_type.category {
                    line.push_str(&format!(" ({category})"));
                }
                if let Some(source) = &data_type.source {
                    line.push_str(match locale {
                        Locale::En | Locale::UsCa => ": collected from ",
                        Locale::Ru => ": источник - ",
                    });
                    line.push_str(source);
                }
                line
            })
            .collect::<Vec<_>>()
            .join("\n");
    }

    match locale {
        Locale::En | Locale::UsCa => "- Technical request data such as IP address, user agent, and request logs.\n- Account, contact, or form data only if the service exposes forms or user input flows.".to_owned(),
        Locale::Ru => "- Технические данные запроса: IP-адрес, user agent и журналы обращений.\n- Контактные или иные данные из форм только при наличии пользовательского ввода.".to_owned(),
    }
}

fn render_purposes(schema: Option<&PolicySchema>, locale: Locale) -> String {
    if let Some(schema) = schema.filter(|schema| !schema.purposes.is_empty()) {
        return schema
            .purposes
            .iter()
            .map(|purpose| {
                let mut line = format!("- {}", purpose.name);
                if let Some(legal_basis) = &purpose.legal_basis {
                    line.push_str(match locale {
                        Locale::En | Locale::UsCa => " / lawful basis: ",
                        Locale::Ru => " / правовое основание: ",
                    });
                    line.push_str(legal_basis);
                }
                if let Some(description) = &purpose.description {
                    line.push_str(" — ");
                    line.push_str(description);
                }
                line
            })
            .collect::<Vec<_>>()
            .join("\n");
    }

    match locale {
        Locale::En | Locale::UsCa => "- Service delivery and security.\n- Compliance with legal obligations.\n- Analytics only where detected and supported by a valid legal basis.".to_owned(),
        Locale::Ru => "- Предоставление и защита сервиса.\n- Исполнение требований законодательства.\n- Аналитика только при наличии выявленного использования и применимого правового основания.".to_owned(),
    }
}

fn render_analytics(analysis: Option<&AnalysisReport>, locale: Locale) -> String {
    match analysis {
        Some(report) if !report.features.analytics.is_empty() => match locale {
            Locale::En | Locale::UsCa => format!(
                "Detected analytics providers: {}. Non-essential analytics must be disclosed and controlled by consent or another documented lawful basis.",
                format_providers(&report.features.analytics)
            ),
            Locale::Ru => format!(
                "Обнаружены сервисы аналитики: {}. Использование аналитики должно быть раскрыто в политике и осуществляться при наличии согласия или иного допустимого основания.",
                format_providers(&report.features.analytics)
            ),
        },
        Some(_) => match locale {
            Locale::En | Locale::UsCa => "AVRORA did not detect Google Analytics or Yandex Metrika in the fetched HTML.".to_owned(),
            Locale::Ru => "AVRORA не обнаружила Google Analytics или Яндекс Метрику в полученном HTML.".to_owned(),
        },
        None => match locale {
            Locale::En | Locale::UsCa => "No scan evidence was provided. Analytics use must be declared if enabled in production.".to_owned(),
            Locale::Ru => "Результаты сканирования не переданы. Использование аналитики должно быть указано, если она включена в продукте.".to_owned(),
        },
    }
}

fn render_cookies(analysis: Option<&AnalysisReport>, locale: Locale) -> String {
    match analysis {
        Some(report) if report.features.cookie_indicators => match locale {
            Locale::En | Locale::UsCa => "Cookie or browser-storage indicators were detected. Non-essential cookies should be categorized, disclosed, and gated where required.".to_owned(),
            Locale::Ru => "Обнаружены признаки cookies или browser storage. Необязательные cookies должны быть описаны, разделены по целям и применяться только при наличии необходимого основания.".to_owned(),
        },
        Some(_) => match locale {
            Locale::En | Locale::UsCa => "No material cookie or browser-storage indicators were detected in fetched HTML. Server-side or post-interaction behavior still requires review.".to_owned(),
            Locale::Ru => "В полученном HTML существенные признаки cookies или browser storage не обнаружены. Серверное поведение и сценарии после взаимодействия требуют отдельной проверки.".to_owned(),
        },
        None => match locale {
            Locale::En | Locale::UsCa => "Cookie use is not confirmed by scan evidence and must be verified against production behavior.".to_owned(),
            Locale::Ru => "Использование cookies не подтверждено сканированием и должно быть сверено с фактической работой продукта.".to_owned(),
        },
    }
}

fn render_forms(analysis: Option<&AnalysisReport>, locale: Locale) -> String {
    match analysis {
        Some(report) if report.features.forms.collects_personal_data() => match locale {
            Locale::En | Locale::UsCa => format!(
                "Detected forms: {}; email inputs: {}; password inputs: {}; telephone inputs: {}; text/search inputs: {}. Each form must show or link the applicable privacy terms before submission.",
                report.features.forms.total_forms,
                report.features.forms.email_inputs,
                report.features.forms.password_inputs,
                report.features.forms.telephone_inputs,
                report.features.forms.text_inputs + report.features.forms.textarea_inputs + report.features.forms.file_inputs
            ),
            Locale::Ru => format!(
                "Обнаружены формы: {}; email-поля: {}; password-поля: {}; telephone-поля: {}; text/search-поля: {}. До отправки формы пользователю должны быть доступны политика и условия обработки персональных данных.",
                report.features.forms.total_forms,
                report.features.forms.email_inputs,
                report.features.forms.password_inputs,
                report.features.forms.telephone_inputs,
                report.features.forms.text_inputs + report.features.forms.textarea_inputs + report.features.forms.file_inputs
            ),
        },
        Some(_) => match locale {
            Locale::En | Locale::UsCa => "No personal-data form inputs were detected in fetched HTML.".to_owned(),
            Locale::Ru => "В полученном HTML поля форм для персональных данных не обнаружены.".to_owned(),
        },
        None => match locale {
            Locale::En | Locale::UsCa => "Form behavior was not scanned and must be reviewed before publication.".to_owned(),
            Locale::Ru => "Поведение форм не проверено сканированием и должно быть отдельно проанализировано перед публикацией.".to_owned(),
        },
    }
}

fn render_third_parties(
    schema: Option<&PolicySchema>,
    analysis: Option<&AnalysisReport>,
    locale: Locale,
) -> String {
    let mut entries = Vec::new();

    if let Some(schema) = schema {
        entries.extend(schema.third_parties.iter().map(|party| {
            let mut line = format!("- {}", party.name);
            if let Some(purpose) = &party.purpose {
                line.push_str(": ");
                line.push_str(purpose);
            }
            if let Some(country) = &party.country {
                line.push_str(" (");
                line.push_str(country);
                line.push(')');
            }
            line
        }));
    }

    if let Some(report) = analysis {
        entries.extend(report.features.analytics.iter().map(|provider| {
            format!(
                "- {}: {}",
                provider_name(provider),
                match locale {
                    Locale::En | Locale::UsCa => "analytics and aggregated usage measurement",
                    Locale::Ru => "аналитика и агрегированное измерение использования",
                }
            )
        }));
    }

    if entries.is_empty() {
        return match locale {
            Locale::En | Locale::UsCa => "- No third parties are declared in the schema or detected by the MVP scan. Add processors before publishing if production behavior differs.".to_owned(),
            Locale::Ru => "- Третьи лица не указаны в схеме и не выявлены MVP-сканированием. Если фактическое поведение продукта отличается, обработчики должны быть добавлены до публикации.".to_owned(),
        };
    }

    entries.join("\n")
}

fn render_legal_requirements(evaluations: &[RuleEvaluation], locale: Locale) -> String {
    evaluations
        .iter()
        .filter(|evaluation| evaluation.applies)
        .map(|evaluation| match locale {
            Locale::En | Locale::UsCa => format!(
                "- [{}] severity {}: {}",
                evaluation.rule_id, evaluation.severity, evaluation.requirement
            ),
            Locale::Ru => format!(
                "- [{}] критичность {}: {}",
                evaluation.rule_id, evaluation.severity, evaluation.requirement
            ),
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn provider_name(provider: &crate::analyzer::AnalyticsProvider) -> &'static str {
    match provider {
        crate::analyzer::AnalyticsProvider::GoogleAnalytics => "Google Analytics",
        crate::analyzer::AnalyticsProvider::YandexMetrika => "Yandex Metrika",
        crate::analyzer::AnalyticsProvider::Matomo => "Matomo",
        crate::analyzer::AnalyticsProvider::Plausible => "Plausible",
        crate::analyzer::AnalyticsProvider::Amplitude => "Amplitude",
        crate::analyzer::AnalyticsProvider::Segment => "Segment",
    }
}
