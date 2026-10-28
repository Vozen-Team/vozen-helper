use super::*;
use helper_store::{
    ConfigImportFeature, ConfigImportLimits, ImportSubscription, SkippedImportSetting,
};
use std::collections::BTreeMap;

#[cfg(test)]
tokio::task_local! { pub(super) static TEST_SNAPSHOT: DiscordGuildSnapshot; }

#[cfg(test)]
mod tests;

type ApiResult<T> = Result<T, (StatusCode, Json<ApiError>)>;
type PortableFeatures = BTreeMap<String, (Option<bool>, Option<serde_json::Value>)>;
type ClassifiedSettings = (PortableFeatures, Vec<SkippedImportSetting>);

fn invalid() -> (StatusCode, Json<ApiError>) {
    client_error(StatusCode::BAD_REQUEST, "invalid_config_import")
}

// The registry owns portable config. Runtime projections and publication IDs
// in old exports are reported, never interpreted as trusted resource identity.
fn portable_features(settings: &[(String, String)]) -> ApiResult<ClassifiedSettings> {
    let mut features = BTreeMap::<String, (Option<bool>, Option<serde_json::Value>)>::new();
    let mut skipped = Vec::new();
    for (name, value) in settings {
        let (key, is_config) = if let Some(key) = name.strip_prefix("feature.config.") {
            (key, true)
        } else if let Some(key) = name.strip_prefix("feature.") {
            (key, false)
        } else {
            skipped.push(SkippedImportSetting {
                key: name.clone(),
                reason: "nonportable_runtime_or_unvalidated_setting".into(),
            });
            continue;
        };
        if key == "management.nickname" {
            skipped.push(SkippedImportSetting {
                key: name.clone(),
                reason: "requires_dedicated_nickname_publication".into(),
            });
            continue;
        }
        if key == "support.welcome_channel" {
            skipped.push(SkippedImportSetting {
                key: name.clone(),
                reason: "merged_into_support.welcome".into(),
            });
            continue;
        }
        if feature_definition(key).is_none() || feature_adapter(key).is_none() {
            return Err(invalid());
        }
        let entry = features.entry(key.into()).or_default();
        if is_config {
            let config: serde_json::Value = serde_json::from_str(value).map_err(|_| invalid())?;
            if !config.is_object() || entry.1.replace(config).is_some() {
                return Err(invalid());
            }
        } else {
            let enabled = match value.as_str() {
                "true" => true,
                "false" => false,
                _ => return Err(invalid()),
            };
            if entry.0.replace(enabled).is_some() {
                return Err(invalid());
            }
        }
    }
    Ok((features, skipped))
}

fn strict_config_types(key: &str, config: &serde_json::Value) -> ApiResult<()> {
    let adapter = feature_adapter(key).ok_or_else(invalid)?;
    let descriptor = adapter.descriptor();
    for (name, value) in config.as_object().ok_or_else(invalid)? {
        let field = descriptor.schema["sections"]
            .as_array()
            .into_iter()
            .flatten()
            .flat_map(|section| section["fields"].as_array().into_iter().flatten())
            .find(|field| field["key"].as_str() == Some(name));
        let default = descriptor.defaults.get(name);
        let valid = if default.is_some_and(serde_json::Value::is_null) {
            value.is_null() || value.is_string()
        } else if let Some(field) = field {
            match field["kind"].as_str().unwrap_or("text") {
                "toggle" => value.is_boolean(),
                "number" | "slider" => {
                    let fractional = default.is_some_and(serde_json::Value::is_f64)
                        || ["min", "max", "step"]
                            .iter()
                            .any(|bound| field[*bound].is_f64());
                    if fractional {
                        value.as_f64().is_some_and(f64::is_finite)
                    } else {
                        value.as_i64().is_some()
                    }
                }
                "tags" | "channels" | "roles" => value
                    .as_array()
                    .is_some_and(|items| items.iter().all(serde_json::Value::is_string)),
                _ => value.is_string(),
            }
        } else if key == "community.levels" && name == "rankCard" {
            value.is_object()
        } else if let Some(default) = default {
            (default.is_boolean() && value.is_boolean())
                || (default.is_number()
                    && if default.is_f64() {
                        value.as_f64().is_some_and(f64::is_finite)
                    } else {
                        value.as_i64().is_some()
                    })
                || (default.is_string() && value.is_string())
                || (default.is_array() && value.is_array())
                || (default.is_object() && value.is_object())
        } else {
            false
        };
        if !valid {
            return Err(invalid());
        }
    }
    Ok(())
}

pub(super) async fn import_config(
    State(state): State<Arc<ApiState>>,
    headers: HeaderMap,
    Json(document): Json<serde_json::Value>,
) -> ApiResult<Json<serde_json::Value>> {
    let claims = require_mutation_auth(&state, &headers).await?;
    let prepared =
        Store::prepare_guild_config_import(&claims.guild_id, &document).map_err(|_| invalid())?;
    let (features, skipped) = portable_features(&prepared.settings)?;
    let mut current_states = BTreeMap::new();
    let mut imported_enabled = BTreeMap::new();
    for (key, (flag, _)) in &features {
        let current = state
            .store
            .get_feature_setting(&claims.guild_id, key)
            .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?;
        let requested = if let Some(current) = &current {
            current.enabled
        } else {
            let mut requested = None;
            for setting in [
                Some(feature_key(key)),
                runtime_feature_key(key).map(str::to_owned),
            ]
            .into_iter()
            .flatten()
            {
                if let Some(value) = state
                    .store
                    .get_setting(&claims.guild_id, &setting)
                    .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?
                {
                    requested = Some(value.parse::<bool>().map_err(|_| invalid())?);
                    break;
                }
            }
            requested.unwrap_or(false)
        };
        imported_enabled.insert(key.clone(), flag.unwrap_or(requested));
        current_states.insert(key.clone(), current);
    }
    let mut writes = Vec::new();
    for (key, (_, imported_config)) in features {
        let current = current_states.remove(&key).unwrap();
        let enabled = imported_enabled[&key];
        let mut config = if let Some(config) = imported_config {
            config
        } else if let Some(current) = &current {
            serde_json::from_str(&current.config_json).map_err(|_| invalid())?
        } else {
            state
                .store
                .get_setting(&claims.guild_id, &feature_config_key(&key))
                .map_err(|_| client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error"))?
                .and_then(|raw| serde_json::from_str(&raw).ok())
                .unwrap_or_else(|| feature_adapter(&key).unwrap().descriptor().defaults)
        };
        if key == "community.levels" {
            config["bannerEnabled"] = serde_json::json!(true);
        }
        strict_config_types(&key, &config)?;
        if enabled {
            require_feature_premium(&state, &claims, &key).await?;
        }
        if !feature_configurable_for(&state, &key) {
            return Err(client_error(
                StatusCode::NOT_IMPLEMENTED,
                "feature_not_available",
            ));
        }
        let request = FeaturePreflightRequest {
            config: config.clone(),
            enabled,
        };
        let checked = if key == "management.nickname" {
            nickname_preflight_for_claims(&state, &claims, request).await?
        } else if matches!(key.as_str(), "protection.antispam" | "protection.antiscam") {
            preflight(
                State(state.clone()),
                headers.clone(),
                Json(PreflightRequest {
                    operation: format!("{key}.publish"),
                    config: config.clone(),
                    enabled,
                }),
            )
            .await?
        } else {
            generic_feature_preflight_with_import(
                State(state.clone()),
                headers.clone(),
                key.clone(),
                request,
                Some(&imported_enabled),
            )
            .await?
        };
        if checked.0["ok"].as_bool() != Some(true) {
            return Err(client_error(
                StatusCode::PRECONDITION_FAILED,
                "feature_preflight_failed",
            ));
        }
        let subscription = match key.as_str() {
            "social.youtube" => ImportSubscription::YouTube(
                prepare_youtube_feature(&state, &claims, &config, enabled).await?,
            ),
            "social.rss" | "social.podcasts" => ImportSubscription::Rss(
                prepare_rss_feature(&state, &claims, &config, enabled).await?,
            ),
            "social.bluesky" => ImportSubscription::Bluesky(
                prepare_bluesky_feature(&state, &claims, &config, enabled).await?,
            ),
            "social.twitch" => ImportSubscription::Twitch(
                prepare_twitch_feature_read_only(&state, &claims, &config, enabled).await?,
            ),
            "social.tiktok" => ImportSubscription::TikTok(
                prepare_tiktok_feature(&state, &claims, &config, enabled).await?,
            ),
            "social.instagram" => ImportSubscription::Instagram(
                prepare_instagram_feature(&state, &claims, &config, enabled).await?,
            ),
            "social.kick" => ImportSubscription::Kick(
                prepare_kick_feature(&state, &claims, &config, enabled).await?,
            ),
            _ => ImportSubscription::None,
        };
        let enabled_value = enabled.to_string();
        let mut projections = vec![
            (feature_key(&key), enabled_value.clone()),
            (feature_config_key(&key), config.to_string()),
        ];
        projections.extend(runtime_projection_pairs(&key, &config));
        if let Some(runtime_key) = runtime_feature_key(&key) {
            projections.push((runtime_key.into(), enabled_value));
        }
        writes.push(ConfigImportFeature {
            key,
            enabled,
            config_json: config.to_string(),
            expected_revision: current.map(|row| row.revision).unwrap_or(0),
            projections,
            subscription,
        });
    }
    let plan = effective_plan(&state, &claims).await;
    if !prepared.workflows.is_empty() {
        require_feature_premium(&state, &claims, "management.workflows").await?;
    }
    let (_, workflow_count, reply_length) = workflow_limits(&state, &claims.guild_id, &plan);
    let (tag_count, tag_length) = custom_command_limits(&state, &claims.guild_id);
    let mut limits = ConfigImportLimits {
        tags: tag_count as usize,
        workflows: workflow_count as usize,
        tag_length,
        reply_length,
    };
    for feature in &writes {
        let config: serde_json::Value =
            serde_json::from_str(&feature.config_json).map_err(|_| invalid())?;
        if feature.key == "management.workflows" {
            if let Some(value) = config["maxWorkflows"].as_u64() {
                limits.workflows = (value as usize).min(quota_limit(&plan, "workflows") as usize);
            }
            if let Some(value) = config["maxReplyLength"].as_u64() {
                limits.reply_length = value as usize;
            }
        }
        if feature.key == "management.custom_commands" {
            if let Some(value) = config["maxTags"].as_u64() {
                limits.tags = value as usize;
            }
            if let Some(value) = config["maxResponseLength"].as_u64() {
                limits.tag_length = value as usize;
            }
        }
    }
    state
        .store
        .validate_guild_config_import_limits(&claims.guild_id, &prepared, &limits)
        .map_err(|_| invalid())?;
    // Provider registration is idempotent and shared across guilds; defer it
    // until every feature and array has passed validation. SQLite remains the
    // atomic boundary for configuration, projections, revisions and arrays.
    for feature in &writes {
        if feature.enabled
            && let ImportSubscription::Twitch(Some(subscription)) = &feature.subscription
        {
            ensure_twitch_subscription(&state, subscription).await?;
        }
    }
    let result = state.store.apply_guild_config_import(
        &claims.guild_id,
        &prepared,
        &claims.user_id,
        &writes,
        &skipped,
        &limits,
    );
    let summary = result.map_err(|error| {
        if error.to_string().starts_with("feature_revision_conflict:") {
            client_error(StatusCode::CONFLICT, "feature_revision_conflict")
        } else {
            client_error(StatusCode::INTERNAL_SERVER_ERROR, "store_error")
        }
    })?;
    Ok(Json(
        serde_json::json!({"ok":true,"guildId":claims.guild_id,"imported":summary,"skippedSettingsCount":skipped.len()}),
    ))
}
