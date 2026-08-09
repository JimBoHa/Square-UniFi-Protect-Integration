use std::{sync::Arc, time::Duration};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use reqwest::{Client, Method, StatusCode, header};
use serde_json::{Value, json};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use tokio::sync::Mutex;
use url::Url;

use crate::{AppError, AppResult, models::PaymentFacts, store::validate_camera_id};

pub const SQUARE_VERSION: &str = "2025-01-23";
pub const SQUARE_WEBHOOK_SUBSCRIPTION_NAME: &str = "square-unifi-protect";
const SQUARE_PRODUCTION_URL: &str = "https://connect.squareup.com";
const SQUARE_SANDBOX_URL: &str = "https://connect.squareupsandbox.com";

#[derive(Clone)]
pub struct SquareClient {
    client: Client,
    base_url: &'static str,
    pub environment: String,
}

impl SquareClient {
    pub fn new(access_token: &str, environment: &str) -> AppResult<Self> {
        if access_token.is_empty() || access_token.len() > 16_384 || has_control(access_token) {
            return Err(AppError::Unprocessable(
                "Invalid Square access token".into(),
            ));
        }
        let base_url = square_base_url(environment)?;
        let mut headers = header::HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            header::HeaderValue::from_str(&format!("Bearer {access_token}"))
                .map_err(AppError::internal)?,
        );
        headers.insert(
            "square-version",
            header::HeaderValue::from_static(SQUARE_VERSION),
        );
        headers.insert(
            header::CONTENT_TYPE,
            header::HeaderValue::from_static("application/json"),
        );
        let client = Client::builder()
            .default_headers(headers)
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(AppError::internal)?;
        Ok(Self {
            client,
            base_url,
            environment: environment.to_owned(),
        })
    }

    async fn request_json(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, String)],
        body: Option<&Value>,
        retry_idempotent: bool,
    ) -> AppResult<Value> {
        let url = format!("{}{path}", self.base_url);
        let mut attempt = 0_u32;
        loop {
            let mut request = self.client.request(method.clone(), &url).query(query);
            if let Some(body) = body {
                request = request.json(body);
            }
            let response = match request.send().await {
                Ok(response) => response,
                Err(error) if retry_idempotent && attempt < 3 => {
                    tracing::warn!(%error, %path, "Square request had a network error; retrying");
                    tokio::time::sleep(retry_delay(attempt, None)).await;
                    attempt += 1;
                    continue;
                }
                Err(error) => {
                    return Err(AppError::Upstream(format!(
                        "Network error while contacting Square: {error}"
                    )));
                }
            };
            let status = response.status();
            if retry_idempotent
                && attempt < 3
                && matches!(status.as_u16(), 429 | 500 | 502 | 503 | 504)
            {
                tokio::time::sleep(retry_delay(attempt, response.headers().get("retry-after")))
                    .await;
                attempt += 1;
                continue;
            }
            if status == StatusCode::UNAUTHORIZED {
                return Err(AppError::Unauthorized(
                    "Square rejected the access token".into(),
                ));
            }
            if status == StatusCode::FORBIDDEN {
                return Err(AppError::Forbidden(
                    "Square rejected the token's permissions".into(),
                ));
            }
            if !status.is_success() {
                return Err(AppError::Upstream(format!(
                    "Square request {path} failed (HTTP {})",
                    status.as_u16()
                )));
            }
            return response
                .json::<Value>()
                .await
                .map_err(|_| AppError::Upstream("Square returned a non-JSON response".into()));
        }
    }

    pub async fn list_locations(&self) -> AppResult<Vec<Value>> {
        let payload = self
            .request_json(Method::GET, "/v2/locations", &[], None, true)
            .await?;
        object_array(&payload, "locations")?
            .iter()
            .map(|location| {
                let id = required_text(location, "id", "Square location id")?;
                Ok(json!({
                    "id": id,
                    "name": optional_text(location, "name", "Square location name")?,
                    "status": optional_text(location, "status", "Square location status")?,
                }))
            })
            .collect()
    }

    pub async fn merchant_id(&self) -> AppResult<String> {
        let payload = self
            .request_json(Method::GET, "/v2/merchants/me", &[], None, true)
            .await?;
        let merchant = payload
            .get("merchant")
            .and_then(Value::as_object)
            .ok_or_else(|| AppError::Upstream("Square returned an invalid merchant".into()))?;
        merchant
            .get("id")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
            .ok_or_else(|| {
                AppError::Upstream("Square did not return the access token's merchant id".into())
            })
    }

    pub async fn payment_page(
        &self,
        location_id: Option<&str>,
        updated_at_begin_time: Option<&str>,
        cursor: Option<&str>,
        limit: usize,
    ) -> AppResult<(Vec<Value>, Option<String>)> {
        let mut query = vec![
            ("sort_field", "UPDATED_AT".into()),
            ("sort_order", "ASC".into()),
            ("limit", limit.clamp(1, 100).to_string()),
        ];
        if let Some(location_id) = location_id {
            query.push(("location_id", location_id.to_owned()));
        }
        if let Some(begin) = updated_at_begin_time {
            query.push(("updated_at_begin_time", begin.to_owned()));
        }
        if let Some(value) = cursor {
            query.push(("cursor", value.to_owned()));
        }
        let payload = self
            .request_json(Method::GET, "/v2/payments", &query, None, true)
            .await?;
        let page = object_array(&payload, "payments")?.to_vec();
        let cursor = match payload.get("cursor") {
            None | Some(Value::Null) => None,
            Some(Value::String(value)) if value.is_empty() => None,
            Some(Value::String(value)) if value.len() <= 4096 && !has_control(value) => {
                Some(value.clone())
            }
            _ => {
                return Err(AppError::Upstream(
                    "Square returned an invalid pagination cursor".into(),
                ));
            }
        };
        Ok((page, cursor))
    }

    pub async fn list_webhook_subscriptions(&self) -> AppResult<Vec<Value>> {
        let mut subscriptions = Vec::new();
        let mut cursor: Option<String> = None;
        let mut seen = std::collections::HashSet::new();
        for _ in 0..100 {
            let mut query = vec![("limit", "100".into())];
            if let Some(value) = cursor.as_ref() {
                query.push(("cursor", value.clone()));
            }
            let payload = self
                .request_json(
                    Method::GET,
                    "/v2/webhooks/subscriptions",
                    &query,
                    None,
                    true,
                )
                .await?;
            subscriptions.extend(object_array(&payload, "subscriptions")?.iter().cloned());
            let next = payload
                .get("cursor")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty());
            let Some(next) = next else {
                return Ok(subscriptions);
            };
            if !seen.insert(next.to_owned()) {
                return Err(AppError::Upstream(
                    "Square returned a repeated pagination cursor".into(),
                ));
            }
            cursor = Some(next.to_owned());
        }
        Err(AppError::Upstream(
            "Square webhook subscription pagination exceeded safety limit".into(),
        ))
    }

    pub async fn create_webhook_subscription(
        &self,
        notification_url: &str,
        idempotency_key: &str,
    ) -> AppResult<Value> {
        let body = json!({
            "idempotency_key": idempotency_key,
            "subscription": {
                "name": SQUARE_WEBHOOK_SUBSCRIPTION_NAME,
                "notification_url": notification_url,
                "event_types": ["payment.created", "payment.updated"],
                "api_version": SQUARE_VERSION,
            }
        });
        let payload = self
            .request_json(
                Method::POST,
                "/v2/webhooks/subscriptions",
                &[],
                Some(&body),
                true,
            )
            .await?;
        payload.get("subscription").cloned().ok_or_else(|| {
            AppError::Upstream("Square returned an invalid webhook subscription".into())
        })
    }

    pub async fn update_webhook_subscription(
        &self,
        id: &str,
        notification_url: &str,
    ) -> AppResult<Value> {
        let body = json!({
            "subscription": {
                "notification_url": notification_url,
                "event_types": ["payment.created", "payment.updated"],
                "enabled": true,
            }
        });
        let payload = self
            .request_json(
                Method::PUT,
                &format!("/v2/webhooks/subscriptions/{id}"),
                &[],
                Some(&body),
                true,
            )
            .await?;
        payload.get("subscription").cloned().ok_or_else(|| {
            AppError::Upstream("Square returned an invalid webhook subscription".into())
        })
    }

    pub async fn webhook_signature_key(&self, id: &str) -> AppResult<String> {
        let payload = self
            .request_json(
                Method::GET,
                &format!("/v2/webhooks/subscriptions/{id}"),
                &[],
                None,
                true,
            )
            .await?;
        payload
            .pointer("/subscription/signature_key")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
            .ok_or_else(|| {
                AppError::Upstream("Square did not return the webhook signature key".into())
            })
    }
}

#[derive(Clone)]
pub struct ProtectClient {
    host: String,
    username: String,
    password: String,
    api_key: Option<String>,
    session_client: Client,
    integration_client: Client,
    csrf_token: Arc<Mutex<Option<String>>>,
}

impl ProtectClient {
    pub fn new(
        host: &str,
        username: &str,
        password: &str,
        verify_ssl: bool,
        api_key: Option<&str>,
    ) -> AppResult<Self> {
        let host = validate_protect_host(host)?;
        if api_key.is_some_and(|value| value.len() > 512 || has_control(value)) {
            return Err(AppError::Unprocessable(
                "Invalid UniFi Protect API key".into(),
            ));
        }
        let session_client = Client::builder()
            .cookie_store(true)
            .tls_danger_accept_invalid_certs(!verify_ssl)
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(AppError::internal)?;
        let integration_client = Client::builder()
            .tls_danger_accept_invalid_certs(!verify_ssl)
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(AppError::internal)?;
        Ok(Self {
            host,
            username: username.to_owned(),
            password: password.to_owned(),
            api_key: api_key
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned),
            session_client,
            integration_client,
            csrf_token: Arc::new(Mutex::new(None)),
        })
    }

    async fn login(&self) -> AppResult<()> {
        let url = format!("https://{}/api/auth/login", self.host);
        for attempt in 0..=3 {
            let response = self
                .session_client
                .post(&url)
                .json(&json!({
                    "username": self.username,
                    "password": self.password,
                    "rememberMe": true,
                }))
                .send()
                .await
                .map_err(|error| {
                    AppError::Upstream(format!(
                        "Network error while contacting UniFi Protect: {error}"
                    ))
                })?;
            if response.status() == StatusCode::TOO_MANY_REQUESTS && attempt < 3 {
                tokio::time::sleep(retry_delay(attempt, response.headers().get("retry-after")))
                    .await;
                continue;
            }
            if matches!(
                response.status(),
                StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
            ) {
                return Err(AppError::Unauthorized(
                    "UniFi Protect rejected the credentials".into(),
                ));
            }
            if !response.status().is_success() {
                return Err(AppError::Upstream(format!(
                    "UniFi Protect login failed (HTTP {})",
                    response.status().as_u16()
                )));
            }
            let csrf = response
                .headers()
                .get("x-csrf-token")
                .or_else(|| response.headers().get("x-updated-csrf-token"))
                .and_then(|value| value.to_str().ok())
                .map(ToOwned::to_owned);
            *self.csrf_token.lock().await = csrf;
            return Ok(());
        }
        unreachable!()
    }

    async fn session_request(&self, method: Method, path: &str) -> AppResult<reqwest::Response> {
        if self.csrf_token.lock().await.is_none() {
            self.login().await?;
        }
        for attempt in 0..=1 {
            let mut request = self
                .session_client
                .request(method.clone(), format!("https://{}{path}", self.host));
            if let Some(csrf) = self.csrf_token.lock().await.clone() {
                request = request.header("x-csrf-token", csrf);
            }
            let response = request.send().await.map_err(|error| {
                AppError::Upstream(format!(
                    "Network error while contacting UniFi Protect: {error}"
                ))
            })?;
            if response.status() == StatusCode::UNAUTHORIZED && attempt == 0 {
                self.login().await?;
                continue;
            }
            return Ok(response);
        }
        unreachable!()
    }

    pub async fn cameras_with_console_identity(&self) -> AppResult<(Vec<Value>, Option<String>)> {
        let response = self
            .session_request(Method::GET, "/proxy/protect/api/bootstrap")
            .await?;
        require_success(&response, "UniFi Protect camera request")?;
        let payload: Value = response
            .json()
            .await
            .map_err(|_| AppError::Upstream("UniFi Protect camera response was not JSON".into()))?;
        let cameras = payload
            .get("cameras")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                AppError::Upstream("UniFi Protect camera response was invalid".into())
            })?;
        let normalized = cameras
            .iter()
            .map(|camera| {
                let id = required_text(camera, "id", "Protect camera id")?;
                validate_camera_id(&id)?;
                let name = optional_text(camera, "name", "Protect camera name")?;
                let market_name = optional_text(camera, "marketName", "Protect camera market name")?;
                let state = optional_text(camera, "state", "Protect camera state")?;
                Ok(json!({
                    "id": id,
                    "name": if name.is_empty() { if market_name.is_empty() { id.clone() } else { market_name } } else { name },
                    "state": state,
                }))
            })
            .collect::<AppResult<Vec<_>>>()?;
        let console_id = ["id", "mac"].iter().find_map(|field| {
            payload
                .pointer(&format!("/nvr/{field}"))
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty() && value.len() <= 256 && !has_control(value))
                .map(ToOwned::to_owned)
        });
        Ok((normalized, console_id))
    }

    pub async fn cameras(&self) -> AppResult<Vec<Value>> {
        Ok(self.cameras_with_console_identity().await?.0)
    }

    pub async fn snapshot(&self, camera_id: &str, ts_ms: Option<i64>) -> AppResult<Vec<u8>> {
        validate_camera_id(camera_id)?;
        let path = if let Some(ts_ms) = ts_ms {
            format!("/proxy/protect/api/cameras/{camera_id}/recording-snapshot?ts={ts_ms}")
        } else {
            format!("/proxy/protect/api/cameras/{camera_id}/snapshot?w=640")
        };
        let response = self.session_request(Method::GET, &path).await?;
        if ts_ms.is_some() && response.status() == StatusCode::NOT_FOUND {
            return Err(AppError::Upstream(format!(
                "No recording available for camera {camera_id} at the requested timestamp"
            )));
        }
        require_success(&response, "UniFi Protect snapshot")?;
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        if !content_type.is_empty()
            && !matches!(
                content_type.as_str(),
                "image/jpeg"
                    | "image/jpg"
                    | "image/pjpeg"
                    | "application/octet-stream"
                    | "binary/octet-stream"
            )
        {
            return Err(AppError::Upstream(
                "UniFi Protect snapshot response was not a JPEG".into(),
            ));
        }
        let bytes = response.bytes().await.map_err(AppError::internal)?.to_vec();
        if !is_complete_jpeg(&bytes) {
            return Err(AppError::Upstream(
                "UniFi Protect snapshot response contained invalid JPEG data".into(),
            ));
        }
        Ok(bytes)
    }

    async fn integration_request(
        &self,
        method: Method,
        path: &str,
    ) -> AppResult<reqwest::Response> {
        let key = self.api_key.as_deref().ok_or_else(|| {
            AppError::Unauthorized("UniFi Protect API key is not configured".into())
        })?;
        let response = self
            .integration_client
            .request(method, format!("https://{}{path}", self.host))
            .header("x-api-key", key)
            .header(header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|error| {
                AppError::Upstream(format!(
                    "Network error while contacting UniFi Protect: {error}"
                ))
            })?;
        if matches!(
            response.status(),
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
        ) {
            return Err(AppError::Unauthorized(
                "UniFi Protect rejected the API key".into(),
            ));
        }
        require_success(&response, "UniFi Protect integration request")?;
        Ok(response)
    }

    pub async fn integration_info(&self) -> AppResult<Value> {
        let response = self
            .integration_request(Method::GET, "/proxy/protect/integration/v1/meta/info")
            .await?;
        let payload: Value = response.json().await.map_err(|_| {
            AppError::Upstream("UniFi Protect integration metadata was not JSON".into())
        })?;
        if payload
            .get("applicationVersion")
            .and_then(Value::as_str)
            .is_none_or(|value| value.trim().is_empty())
        {
            return Err(AppError::Upstream(
                "UniFi Protect integration metadata was invalid".into(),
            ));
        }
        Ok(payload)
    }

    pub async fn trigger_alarm(&self, trigger_id: &str) -> AppResult<()> {
        validate_alarm_trigger_id(trigger_id)?;
        let encoded: String = url::form_urlencoded::byte_serialize(trigger_id.as_bytes()).collect();
        self.integration_request(
            Method::POST,
            &format!("/proxy/protect/integration/v1/alarm-manager/webhook/{encoded}"),
        )
        .await?;
        Ok(())
    }
}

pub fn square_base_url(environment: &str) -> AppResult<&'static str> {
    match environment {
        "production" => Ok(SQUARE_PRODUCTION_URL),
        "sandbox" => Ok(SQUARE_SANDBOX_URL),
        _ => Err(AppError::Unprocessable(
            "environment must be 'production' or 'sandbox'".into(),
        )),
    }
}

pub fn validate_protect_host(value: &str) -> AppResult<String> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 255
        || value.contains(['/', '\\', '@', '?', '#'])
        || value.chars().any(char::is_whitespace)
    {
        return Err(AppError::Unprocessable(
            "Protect host must be a hostname or IP address (optionally with :port), without scheme or path".into(),
        ));
    }
    let url = Url::parse(&format!("https://{value}"))
        .map_err(|_| AppError::Unprocessable("Invalid Protect host".into()))?;
    if url.host_str().is_none() || url.port_or_known_default().is_none() {
        return Err(AppError::Unprocessable("Invalid Protect host".into()));
    }
    Ok(value.to_owned())
}

pub fn validate_alarm_trigger_id(value: &str) -> AppResult<String> {
    let value = value.trim();
    if !(1..=256).contains(&value.len()) || has_control(value) {
        return Err(AppError::Unprocessable(
            "Alarm trigger id must be 1-256 characters without control characters".into(),
        ));
    }
    Ok(value.to_owned())
}

pub fn verify_square_webhook_signature(
    signature_key: &str,
    notification_url: &str,
    body: &[u8],
    signature_header: &str,
) -> bool {
    if signature_key.is_empty() || signature_header.is_empty() {
        return false;
    }
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(signature_key.as_bytes()) else {
        return false;
    };
    mac.update(notification_url.as_bytes());
    mac.update(body);
    let expected = STANDARD.encode(mac.finalize().into_bytes());
    expected.len() == signature_header.len()
        && bool::from(expected.as_bytes().ct_eq(signature_header.as_bytes()))
}

pub fn parse_payment(payment: &Value) -> AppResult<PaymentFacts> {
    let object = payment
        .as_object()
        .ok_or_else(|| AppError::Unprocessable("Payment must be an object".into()))?;
    let amount_money = optional_object(payment, "amount_money")?;
    let total_money = optional_object(payment, "total_money")?;
    let display_money = if total_money.is_empty() {
        &amount_money
    } else {
        &total_money
    };
    let amount = display_money
        .get("amount")
        .or_else(|| amount_money.get("amount"))
        .map(|value| {
            value
                .as_i64()
                .ok_or_else(|| AppError::Unprocessable("Payment amount must be an integer".into()))
        })
        .transpose()?
        .unwrap_or(0);
    let display_currency = display_money.get("currency");
    let currency = if display_currency
        .is_none_or(|value| value.is_null() || value.as_str().is_some_and(str::is_empty))
    {
        amount_money.get("currency")
    } else {
        display_currency
    };
    let currency = match currency {
        None | Some(Value::Null) => "USD".to_owned(),
        Some(Value::String(value)) if value.is_empty() => "USD".to_owned(),
        Some(Value::String(value)) => value.clone(),
        _ => {
            return Err(AppError::Unprocessable(
                "Payment currency must be a string".into(),
            ));
        }
    };
    let refunded_amount = if object.contains_key("refunded_money") {
        let refunded = optional_object(payment, "refunded_money")?;
        let amount = refunded
            .get("amount")
            .and_then(Value::as_i64)
            .filter(|value| *value >= 0)
            .ok_or_else(|| {
                AppError::Unprocessable(
                    "Payment refunded_money.amount must be a non-negative integer".into(),
                )
            })?;
        let refund_currency = refunded
            .get("currency")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                AppError::Unprocessable("Payment refunded_money.currency is required".into())
            })?;
        if refund_currency.len() != 3
            || !refund_currency
                .bytes()
                .all(|value| value.is_ascii_alphabetic() && value.is_ascii_uppercase())
        {
            return Err(AppError::Unprocessable(
                "Payment refunded_money.currency must be an uppercase ISO currency code".into(),
            ));
        }
        if refund_currency != currency {
            return Err(AppError::Unprocessable(
                "Payment refunded_money currency does not match payment".into(),
            ));
        }
        amount
    } else {
        0
    };
    let card_details = optional_object(payment, "card_details")?;
    let card = card_details
        .get("card")
        .map(|value| {
            value.as_object().ok_or_else(|| {
                AppError::Unprocessable("Payment card_details.card must be an object".into())
            })
        })
        .transpose()?
        .cloned()
        .unwrap_or_default();
    let device = optional_object(payment, "device_details")?;
    let offline = optional_object(payment, "offline_payment_details")?;
    let server_created_at = payment_required_text(payment, "created_at", "Payment created_at")?;
    let created_at = if payment.get("is_offline_payment") == Some(&Value::Bool(true)) {
        match offline.get("client_created_at") {
            None | Some(Value::Null) => server_created_at.clone(),
            Some(Value::String(value)) if value.trim().is_empty() => server_created_at.clone(),
            Some(Value::String(value)) => value.trim().to_owned(),
            _ => {
                return Err(AppError::Unprocessable(
                    "Payment offline_payment_details.client_created_at must be a string".into(),
                ));
            }
        }
    } else {
        server_created_at.clone()
    };
    let updated_at = payment_optional_text(payment, "updated_at", "Payment updated_at")?;
    let updated_at = if updated_at.is_empty() {
        server_created_at
    } else {
        updated_at
    };
    Ok(PaymentFacts {
        id: payment_required_text(payment, "id", "Payment id")?,
        ts_ms: parse_timestamp_ms(&created_at)?,
        updated_ts_ms: parse_timestamp_ms(&updated_at)?,
        created_at,
        updated_at,
        amount,
        currency,
        refunded_amount,
        status: payment_optional_text(payment, "status", "Payment status")?,
        location_id: payment_optional_text(payment, "location_id", "Payment location_id")?,
        device_id: payment_map_text(&device, "device_id", "Payment device_details.device_id")?,
        device_name: payment_map_text(
            &device,
            "device_name",
            "Payment device_details.device_name",
        )?,
        card_last4: payment_map_text(&card, "last_4", "Payment card_details.card.last_4")?,
        receipt_url: payment_optional_text(payment, "receipt_url", "Payment receipt_url")?,
    })
}

pub fn oauth_authorize_url(environment: &str, client_id: &str, state: &str) -> AppResult<String> {
    let base = square_base_url(environment)?;
    let mut url = Url::parse(&format!("{base}/oauth2/authorize")).map_err(AppError::internal)?;
    url.query_pairs_mut()
        .append_pair("client_id", client_id)
        .append_pair("scope", "MERCHANT_PROFILE_READ PAYMENTS_READ")
        .append_pair("session", "false")
        .append_pair("state", state);
    Ok(url.into())
}

pub async fn oauth_exchange(
    environment: &str,
    client_id: &str,
    client_secret: &str,
    code: Option<&str>,
    refresh_token: Option<&str>,
) -> AppResult<Value> {
    let base = square_base_url(environment)?;
    let mut body = json!({
        "client_id": client_id,
        "client_secret": client_secret,
    });
    if let Some(code) = code {
        body["grant_type"] = Value::String("authorization_code".into());
        body["code"] = Value::String(code.into());
    } else if let Some(refresh) = refresh_token {
        body["grant_type"] = Value::String("refresh_token".into());
        body["refresh_token"] = Value::String(refresh.into());
    } else {
        return Err(AppError::Unprocessable(
            "code or refresh_token is required".into(),
        ));
    }
    let response = Client::new()
        .post(format!("{base}/oauth2/token"))
        .json(&body)
        .send()
        .await
        .map_err(|error| {
            AppError::Upstream(format!("Network error while contacting Square: {error}"))
        })?;
    if matches!(response.status().as_u16(), 400 | 401 | 403) {
        return Err(AppError::Unauthorized(
            "Square rejected the OAuth request".into(),
        ));
    }
    require_success(&response, "Square OAuth")?;
    let payload: Value = response
        .json()
        .await
        .map_err(|_| AppError::Upstream("Square returned a non-JSON response".into()))?;
    if payload
        .get("access_token")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        return Err(AppError::Upstream(
            "Square returned an invalid OAuth response".into(),
        ));
    }
    Ok(payload)
}

fn parse_timestamp_ms(value: &str) -> AppResult<i64> {
    DateTime::parse_from_rfc3339(value)
        .map(|time| time.with_timezone(&Utc).timestamp_millis())
        .map_err(|_| AppError::Unprocessable("Payment timestamp is invalid".into()))
}

fn object_array<'a>(payload: &'a Value, key: &str) -> AppResult<&'a [Value]> {
    match payload.get(key) {
        None | Some(Value::Null) => Ok(&[]),
        Some(Value::Array(values)) => Ok(values),
        Some(_) => Err(AppError::Upstream(
            "Square returned an invalid response".into(),
        )),
    }
}

fn optional_object(payload: &Value, key: &str) -> AppResult<serde_json::Map<String, Value>> {
    match payload.get(key) {
        None | Some(Value::Null) => Ok(Default::default()),
        Some(Value::Object(value)) => Ok(value.clone()),
        Some(_) => Err(AppError::Unprocessable(format!(
            "Payment {key} must be an object"
        ))),
    }
}

fn required_text(payload: &Value, key: &str, label: &str) -> AppResult<String> {
    payload
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| AppError::Upstream(format!("{label} was missing or invalid")))
}

fn optional_text(payload: &Value, key: &str, label: &str) -> AppResult<String> {
    match payload.get(key) {
        None | Some(Value::Null) => Ok(String::new()),
        Some(Value::String(value)) => Ok(value.clone()),
        Some(_) => Err(AppError::Upstream(format!("{label} was invalid"))),
    }
}

fn payment_required_text(payload: &Value, key: &str, label: &str) -> AppResult<String> {
    match payload.get(key) {
        Some(Value::String(value)) if !value.is_empty() => Ok(value.clone()),
        _ => Err(AppError::Unprocessable(format!(
            "{label} is required and must be a string"
        ))),
    }
}

fn payment_optional_text(payload: &Value, key: &str, label: &str) -> AppResult<String> {
    match payload.get(key) {
        None | Some(Value::Null) => Ok(String::new()),
        Some(Value::String(value)) => Ok(value.clone()),
        _ => Err(AppError::Unprocessable(format!("{label} must be a string"))),
    }
}

fn payment_map_text(
    payload: &serde_json::Map<String, Value>,
    key: &str,
    label: &str,
) -> AppResult<String> {
    match payload.get(key) {
        None | Some(Value::Null) => Ok(String::new()),
        Some(Value::String(value)) => Ok(value.clone()),
        _ => Err(AppError::Unprocessable(format!("{label} must be a string"))),
    }
}

fn retry_delay(attempt: u32, retry_after: Option<&header::HeaderValue>) -> Duration {
    if let Some(seconds) = retry_after
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<f64>().ok())
        .filter(|value| value.is_finite() && *value >= 0.0)
    {
        return Duration::from_secs_f64(seconds.min(10.0));
    }
    Duration::from_secs_f64((0.5 * 2_f64.powi(attempt as i32)).min(10.0))
}

fn require_success(response: &reqwest::Response, label: &str) -> AppResult<()> {
    if response.status().is_success() {
        Ok(())
    } else {
        Err(AppError::Upstream(format!(
            "{label} failed (HTTP {})",
            response.status().as_u16()
        )))
    }
}

fn has_control(value: &str) -> bool {
    value
        .chars()
        .any(|character| character < ' ' || character == '\u{7f}')
}

fn is_complete_jpeg(content: &[u8]) -> bool {
    if !content.starts_with(&[0xff, 0xd8]) {
        return false;
    }
    let mut position = 2;
    let mut in_scan = false;
    let mut saw_frame = false;
    let mut saw_scan = false;
    let mut saw_scan_data = false;
    while position < content.len() {
        if in_scan {
            let Some(relative) = content[position..].iter().position(|byte| *byte == 0xff) else {
                return false;
            };
            let marker_start = position + relative;
            if marker_start + 1 >= content.len() {
                return false;
            }
            if marker_start > position {
                saw_scan_data = true;
            }
            let marker = content[marker_start + 1];
            if marker == 0x00 {
                saw_scan_data = true;
                position = marker_start + 2;
                continue;
            }
            if marker == 0xff {
                position = marker_start + 1;
                continue;
            }
            if (0xd0..=0xd7).contains(&marker) {
                position = marker_start + 2;
                continue;
            }
            position = marker_start;
            in_scan = false;
            continue;
        }
        if content[position] != 0xff {
            return false;
        }
        while position < content.len() && content[position] == 0xff {
            position += 1;
        }
        if position >= content.len() {
            return false;
        }
        let marker = content[position];
        position += 1;
        if marker == 0xd9 {
            return saw_frame && saw_scan && saw_scan_data;
        }
        if marker == 0xd8 || marker == 0x00 {
            return false;
        }
        if marker == 0x01 || (0xd0..=0xd7).contains(&marker) {
            continue;
        }
        if position + 2 > content.len() {
            return false;
        }
        let length = u16::from_be_bytes([content[position], content[position + 1]]) as usize;
        if length < 2 || position + length > content.len() {
            return false;
        }
        if matches!(
            marker,
            0xc0 | 0xc1
                | 0xc2
                | 0xc3
                | 0xc5
                | 0xc6
                | 0xc7
                | 0xc9
                | 0xca
                | 0xcb
                | 0xcd
                | 0xce
                | 0xcf
        ) {
            saw_frame = true;
        }
        if marker == 0xda {
            if !saw_frame {
                return false;
            }
            saw_scan = true;
            in_scan = true;
        }
        position += length;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn square_signature_matches_reference_protocol() {
        let key = "webhook-secret";
        let url = "https://example.test/webhooks/square";
        let body = br#"{"type":"payment.updated"}"#;
        let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes()).unwrap();
        mac.update(url.as_bytes());
        mac.update(body);
        let signature = STANDARD.encode(mac.finalize().into_bytes());
        assert!(verify_square_webhook_signature(key, url, body, &signature));
        assert!(!verify_square_webhook_signature(
            key, url, b"changed", &signature
        ));
    }

    #[test]
    fn parses_square_payment_without_retaining_raw_buyer_data() {
        let payment = json!({
            "id": "PAY_1",
            "created_at": "2026-07-16T15:30:00.000Z",
            "updated_at": "2026-07-16T15:31:00.000Z",
            "amount_money": {"amount": 99, "currency": "USD"},
            "status": "COMPLETED",
            "location_id": "LOC_1",
            "buyer_email_address": "must-not-persist@example.test",
        });
        let facts = parse_payment(&payment).unwrap();
        assert_eq!(facts.id, "PAY_1");
        assert_eq!(facts.amount, 99);
    }

    #[test]
    fn rejects_ambiguous_square_payment_field_types() {
        let base = json!({
            "id": "PAY_1",
            "created_at": "2026-07-16T15:30:00.000Z",
            "amount_money": {"amount": 99, "currency": "USD"},
            "status": "COMPLETED",
        });
        for invalid in [
            {
                let mut value = base.clone();
                value["amount_money"]["amount"] = json!("99");
                value
            },
            {
                let mut value = base.clone();
                value["device_details"] = json!({"device_id": 42});
                value
            },
            {
                let mut value = base.clone();
                value["is_offline_payment"] = json!(true);
                value["offline_payment_details"] = json!({"client_created_at": 42});
                value
            },
            {
                let mut value = base.clone();
                value["refunded_money"] = json!({"amount": 1, "currency": "usd"});
                value
            },
        ] {
            assert!(matches!(
                parse_payment(&invalid),
                Err(AppError::Unprocessable(_))
            ));
        }
    }
}
