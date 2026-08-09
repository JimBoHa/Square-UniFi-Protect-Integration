use std::{fs, sync::Arc};

use chrono::{SecondsFormat, TimeZone, Utc};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;

use crate::{
    AppError, AppResult,
    clients::{ProtectClient, SquareClient, oauth_exchange, parse_payment},
    models::PaymentFacts,
    store::{Store, now_millis},
    thumbnail::{load_policy, prepare_thumbnail, write_thumbnail},
};

const BACKFILL_HOURS: i64 = 24;

#[derive(Clone)]
pub struct SyncEngine {
    store: Store,
    execution: Arc<Mutex<()>>,
    oauth_refresh: Arc<Mutex<()>>,
}

impl SyncEngine {
    pub fn new(store: Store) -> Self {
        Self {
            store,
            execution: Arc::new(Mutex::new(())),
            oauth_refresh: Arc::new(Mutex::new(())),
        }
    }

    pub async fn try_sync(&self) -> AppResult<Option<usize>> {
        let Ok(_execution) = self.execution.try_lock() else {
            return Ok(None);
        };
        self.sync().await.map(Some)
    }

    pub async fn sync(&self) -> AppResult<usize> {
        let _provider_guard = self.store.integration_guard(false)?;
        let square = self
            .square_client()
            .await?
            .ok_or_else(|| AppError::Conflict("Square is not configured".into()))?;
        let protect = match self.verified_protect_client().await {
            Ok(protect) => protect,
            Err(error @ AppError::Conflict(_)) => return Err(error),
            Err(error) => {
                tracing::warn!(%error, "Protect unreachable during sync; deferring camera evidence");
                None
            }
        };
        let locations = square.list_locations().await?;
        let mut count = 0_usize;
        let mut seen = std::collections::HashSet::new();
        for location in locations {
            let Some(location_id) = location.get("id").and_then(Value::as_str) else {
                continue;
            };
            let boundary = now_millis();
            let begin_ms = self
                .store
                .square_poll_watermark(location_id)?
                .map(|value| value - 5 * 60 * 1000)
                .unwrap_or(boundary - BACKFILL_HOURS * 3600 * 1000);
            let begin = Utc
                .timestamp_millis_opt(begin_ms)
                .single()
                .ok_or_else(|| {
                    AppError::internal(anyhow::anyhow!("invalid Square poll watermark"))
                })?
                .to_rfc3339_opts(SecondsFormat::Secs, true);
            let mut cursor = None;
            let mut seen_cursors = std::collections::HashSet::new();
            loop {
                let (page, next_cursor) = square
                    .payment_page(Some(location_id), Some(&begin), cursor.as_deref(), 100)
                    .await?;
                for payment in page {
                    let id = payment.get("id").and_then(Value::as_str).unwrap_or("");
                    if !id.is_empty() && !seen.insert(id.to_owned()) {
                        continue;
                    }
                    match self.ingest_payment(&payment).await {
                        Ok(is_new) => count += usize::from(is_new),
                        Err(AppError::Unprocessable(error)) => {
                            tracing::warn!(%error, "skipping malformed Square payment");
                        }
                        Err(error) => return Err(error),
                    }
                }
                let Some(next_cursor) = next_cursor else {
                    break;
                };
                if !seen_cursors.insert(next_cursor.clone()) {
                    return Err(AppError::Upstream(
                        "Square returned a repeated pagination cursor".into(),
                    ));
                }
                cursor = Some(next_cursor);
            }
            self.store
                .advance_square_poll_watermark(location_id, boundary)?;
        }
        self.drain_protect_queues(protect.as_ref()).await;
        Ok(count)
    }

    pub async fn square_client(&self) -> AppResult<Option<SquareClient>> {
        self.refresh_oauth_token_if_needed().await?;
        square_from_store(&self.store)
    }

    async fn refresh_oauth_token_if_needed(&self) -> AppResult<()> {
        let _refresh = self.oauth_refresh.lock().await;
        let snapshot = self.store.square_oauth_snapshot()?;
        let (Some(client_id), Some(client_secret), Some(refresh_token), Some(expires_at)) = (
            snapshot.client_id.as_deref(),
            snapshot.client_secret.as_deref(),
            snapshot.refresh_token.as_deref(),
            snapshot.token_expires_at.as_deref(),
        ) else {
            return Ok(());
        };
        let Ok(expires_at) = chrono::DateTime::parse_from_rfc3339(expires_at) else {
            return Ok(());
        };
        if expires_at.with_timezone(&Utc) - Utc::now() > chrono::Duration::days(3) {
            return Ok(());
        }
        let environment = snapshot.environment.as_deref().unwrap_or("production");
        let tokens = match oauth_exchange(
            environment,
            client_id,
            client_secret,
            None,
            Some(refresh_token),
        )
        .await
        {
            Ok(tokens) => tokens,
            Err(error) => {
                tracing::warn!(%error, "Square OAuth token refresh failed");
                return Ok(());
            }
        };
        let Some(access_token) = tokens
            .get("access_token")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
        else {
            tracing::warn!("Square OAuth refresh omitted the access token");
            return Ok(());
        };
        let refreshed_token = tokens
            .get("refresh_token")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .unwrap_or(refresh_token);
        let refreshed_expiry = tokens
            .get("expires_at")
            .and_then(Value::as_str)
            .unwrap_or("");
        if !self.store.update_square_oauth_tokens(
            &snapshot,
            access_token,
            refreshed_token,
            refreshed_expiry,
        )? {
            tracing::info!("Discarded Square OAuth refresh after account settings changed");
        }
        Ok(())
    }

    async fn verified_protect_client(&self) -> AppResult<Option<ProtectClient>> {
        let Some(client) = protect_from_store(&self.store)? else {
            return Ok(None);
        };
        let (_, observed) = client.cameras_with_console_identity().await?;
        verify_protect_identity(&self.store, observed.as_deref())?;
        Ok(Some(client))
    }

    pub async fn drain_verified_protect_queues(&self) -> AppResult<()> {
        let _provider_guard = self.store.integration_guard(false)?;
        if let Some(client) = self.verified_protect_client().await? {
            self.drain_protect_queues(Some(&client)).await;
        }
        Ok(())
    }

    pub async fn ingest_payment(&self, payment: &Value) -> AppResult<bool> {
        let facts = parse_payment(payment)?;
        let existing = self.store.get_transaction(&facts.id)?;
        let stale = existing
            .as_ref()
            .is_some_and(|value| facts.updated_ts_ms < value.updated_ts_ms);
        let is_new = self.store.upsert_payment(&facts)?;
        if stale {
            return Ok(false);
        }
        Ok(is_new)
    }

    async fn capture_thumbnail(
        &self,
        protect: &ProtectClient,
        facts: &PaymentFacts,
        camera_id: &str,
        lease_token: &str,
    ) -> AppResult<bool> {
        let image = protect.snapshot(camera_id, Some(facts.ts_ms)).await?;
        let prepared = prepare_thumbnail(&image, &load_policy(&self.store)?);
        if let Some(error) = prepared.error.as_deref() {
            tracing::warn!(%error, "could not compress Protect thumbnail; preserving original");
        }
        let filename = versioned_thumbnail_name(
            &facts.id,
            camera_id,
            facts.ts_ms,
            facts.updated_ts_ms,
            lease_token,
        )?;
        let path = self.store.thumbnail_dir().join(&filename);
        write_thumbnail(&path, &prepared.data)?;
        let attached = self.store.complete_thumbnail_retry(
            &facts.id,
            lease_token,
            camera_id,
            facts.ts_ms,
            &filename,
            prepared.data.len() as i64,
            prepared.policy_revision,
        );
        if !matches!(attached, Ok(true)) {
            let _ = fs::remove_file(path);
        }
        attached
    }

    pub async fn drain_protect_queues(&self, protect: Option<&ProtectClient>) {
        let Some(protect) = protect else {
            return;
        };
        for _ in 0..20 {
            match self.retry_alarms(protect).await {
                Ok(10) => {}
                Ok(_) => break,
                Err(error) => {
                    tracing::warn!(%error, "Protect alarm retry batch failed");
                    break;
                }
            }
        }
        for _ in 0..20 {
            match self.retry_thumbnails(protect).await {
                Ok(10) => {}
                Ok(_) => break,
                Err(error) => {
                    tracing::warn!(%error, "thumbnail retry batch failed");
                    break;
                }
            }
        }
    }

    async fn retry_thumbnails(&self, protect: &ProtectClient) -> AppResult<usize> {
        let jobs = self.store.claim_due_thumbnail_retries(10, now_seconds())?;
        let claimed = jobs.len();
        for (job, lease_token) in jobs {
            let Some(camera_id) = job.camera_id.as_deref() else {
                continue;
            };
            let facts = PaymentFacts {
                id: job.id.clone(),
                ts_ms: job.ts_ms,
                updated_ts_ms: job.updated_ts_ms,
                ..PaymentFacts::default()
            };
            match self
                .capture_thumbnail(protect, &facts, camera_id, &lease_token)
                .await
            {
                Ok(_) => {}
                Err(error) => {
                    self.store.fail_thumbnail_retry(
                        &job.id,
                        &lease_token,
                        camera_id,
                        job.ts_ms,
                        &error.to_string(),
                        now_seconds(),
                    )?;
                    tracing::warn!(transaction_id = %job.id, %error, "thumbnail retry failed");
                }
            }
        }
        Ok(claimed)
    }

    async fn retry_alarms(&self, protect: &ProtectClient) -> AppResult<usize> {
        let Some(trigger) = self.store.get_setting("protect.alarm_trigger_id")? else {
            return Ok(0);
        };
        if trigger.is_empty() {
            return Ok(0);
        }
        let mut completed = 0;
        for transaction_id in self.store.pending_alarm_ids(10)? {
            let Some(claim_token) = self.store.claim_alarm_trigger(&transaction_id)? else {
                continue;
            };
            match protect.trigger_alarm(&trigger).await {
                Ok(()) => {
                    if self
                        .store
                        .mark_alarm_sent(&transaction_id, &claim_token, now_millis())?
                    {
                        completed += 1;
                    }
                }
                Err(error) => {
                    self.store
                        .release_alarm_claim(&transaction_id, &claim_token)?;
                    tracing::warn!(%transaction_id, %error, "Protect alarm delivery failed");
                    break;
                }
            }
        }
        Ok(completed)
    }
}

pub fn square_from_store(store: &Store) -> AppResult<Option<SquareClient>> {
    let Some(access_token) = store.get_setting("square.access_token")? else {
        return Ok(None);
    };
    if access_token.is_empty() {
        return Ok(None);
    }
    let environment = store
        .get_setting("square.environment")?
        .unwrap_or_else(|| "production".into());
    SquareClient::new(&access_token, &environment).map(Some)
}

pub fn protect_from_store(store: &Store) -> AppResult<Option<ProtectClient>> {
    let Some(host) = store.get_setting("protect.host")? else {
        return Ok(None);
    };
    let username = store.get_setting("protect.username")?.unwrap_or_default();
    let password = store.get_setting("protect.password")?.unwrap_or_default();
    if host.is_empty() || username.is_empty() || password.is_empty() {
        return Ok(None);
    }
    let verify_ssl = store
        .get_setting("protect.verify_ssl")?
        .is_some_and(|value| value == "1");
    let api_key = store.get_setting("protect.api_key")?;
    ProtectClient::new(&host, &username, &password, verify_ssl, api_key.as_deref()).map(Some)
}

pub fn verify_protect_identity(store: &Store, observed: Option<&str>) -> AppResult<()> {
    if let Some(expected) = store.get_setting(crate::store::PROTECT_CONSOLE_ID_SETTING)?
        && Some(expected.as_str()) != observed
    {
        return Err(AppError::Conflict(
            "UniFi Protect console identity changed or disappeared; reconnect Protect before processing camera evidence or alarms".into(),
        ));
    }
    Ok(())
}

fn versioned_thumbnail_name(
    payment_id: &str,
    camera_id: &str,
    ts_ms: i64,
    updated_ts_ms: i64,
    lease_token: &str,
) -> AppResult<String> {
    let cleaned: String = payment_id
        .chars()
        .filter(|value| value.is_ascii_alphanumeric() || matches!(value, '_' | '-'))
        .take(48)
        .collect();
    if cleaned.is_empty() {
        return Err(AppError::Unprocessable(
            "Payment id yields no safe filename".into(),
        ));
    }
    let material = format!("{payment_id}\0{camera_id}\0{ts_ms}\0{updated_ts_ms}\0{lease_token}");
    let digest = hex::encode(Sha256::digest(material.as_bytes()));
    Ok(format!("{cleaned}-{ts_ms}-{}.jpg", &digest[..24]))
}

fn now_seconds() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

pub async fn run_poller(engine: SyncEngine, interval: std::time::Duration) {
    let mut timer = tokio::time::interval(interval);
    timer.tick().await;
    loop {
        timer.tick().await;
        if let Err(error) = engine.try_sync().await {
            tracing::warn!(%error, "background Square sync failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versioned_names_are_local_and_collision_resistant() {
        let first = versioned_thumbnail_name("PAY/one", "CAM1", 10, 11, "lease-a").unwrap();
        let second = versioned_thumbnail_name("PAY/one", "CAM1", 10, 11, "lease-b").unwrap();
        assert_ne!(first, second);
        assert!(!first.contains('/'));
        assert!(first.ends_with(".jpg"));
    }
}
