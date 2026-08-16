use std::{
    collections::HashSet,
    env,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
};

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{Request, StatusCode, header},
};
use chrono::{SecondsFormat, TimeZone, Utc};
use reqwest::Client;
use serde_json::{Value, json};
use square_unifi_protect::{
    AppState, Config, DEFAULT_PORT, Store, build_router,
    clients::{ProtectClient, SQUARE_VERSION, SquareClient},
    models::{CameraMappingEntry, PaymentFacts},
    store::now_millis,
    sync::SyncEngine,
};
use tower::ServiceExt;
use uuid::Uuid;

fn required_secret(name: &str) -> String {
    env::var(name).unwrap_or_else(|_| {
        panic!(
            "{name} is required for this opt-in live test. Run scripts/run-live-provider-tests.sh to enter credentials securely."
        )
    })
}

fn app_state(store: Store, data_dir: PathBuf) -> AppState {
    AppState::new(
        store,
        Config {
            data_dir,
            static_dir: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("app/static"),
            bind_host: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: DEFAULT_PORT,
            tls_enabled: false,
            tls_certfile: None,
            tls_keyfile: None,
            cookie_secure: false,
            poll_interval: None,
            bootstrap_secret: None,
        },
    )
}

async fn configured_camera() -> Value {
    let camera_name = required_secret("SPI_TEST_PROTECT_CAMERA_NAME");
    let client = ProtectClient::new(
        &required_secret("SPI_TEST_PROTECT_HOST"),
        &required_secret("SPI_TEST_PROTECT_USERNAME"),
        &required_secret("SPI_TEST_PROTECT_PASSWORD"),
        false,
        None,
    )
    .expect("Protect test settings should be valid");
    client
        .cameras()
        .await
        .expect("Protect credentials or connection failed")
        .into_iter()
        .find(|camera| {
            camera
                .get("name")
                .and_then(Value::as_str)
                .is_some_and(|name| name.trim().eq_ignore_ascii_case(&camera_name))
        })
        .unwrap_or_else(|| panic!("The configured Protect camera was not found"))
}

fn motion_request(token: &str, camera_id: &str, timestamp: i64) -> Request<Body> {
    let payload = json!({
        "timestamp": timestamp,
        "alarm": {
            "name": "Configured camera motion live test",
            "conditions": [{"condition": {"source": "motion"}}],
            "triggers": [{"key": "motion", "device": camera_id}],
        },
    });
    let mut request = Request::builder()
        .method("POST")
        .uri("/webhooks/protect/motion")
        .header(header::HOST, format!("localhost:{DEFAULT_PORT}"))
        .header(header::CONTENT_TYPE, "application/json")
        .header("x-spi-webhook-token", token)
        .body(Body::from(payload.to_string()))
        .unwrap();
    request.extensions_mut().insert(ConnectInfo(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        41_001,
    )));
    request
}

fn payment(id: &str, location_id: &str, timestamp: i64) -> PaymentFacts {
    let created_at = Utc
        .timestamp_millis_opt(timestamp)
        .single()
        .expect("live test timestamp should be valid")
        .to_rfc3339_opts(SecondsFormat::Millis, true);
    PaymentFacts {
        id: id.into(),
        created_at: created_at.clone(),
        ts_ms: timestamp,
        updated_at: created_at,
        updated_ts_ms: timestamp,
        amount: 1,
        currency: "USD".into(),
        status: "COMPLETED".into(),
        location_id: location_id.into(),
        ..PaymentFacts::default()
    }
}

#[tokio::test]
#[ignore = "creates 10 Square Sandbox payments and requires credentials"]
async fn square_sandbox_round_trips_ten_transactions() {
    let access_token = required_secret("SPI_TEST_SQUARE_ACCESS_TOKEN");
    let square = SquareClient::new(&access_token, "sandbox").unwrap();
    let location = square
        .list_locations()
        .await
        .expect("Square credentials or connection failed")
        .into_iter()
        .find(|location| location.get("status").and_then(Value::as_str) == Some("ACTIVE"))
        .expect("Square Sandbox has no active location");
    let location_id = location
        .get("id")
        .and_then(Value::as_str)
        .expect("Square location id is missing");

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .unwrap();
    let mut created = Vec::new();
    for index in 0..10 {
        let response = client
            .post("https://connect.squareupsandbox.com/v2/payments")
            .bearer_auth(&access_token)
            .header("Square-Version", SQUARE_VERSION)
            .json(&json!({
                "source_id": "cnon:card-nonce-ok",
                "idempotency_key": Uuid::new_v4().to_string(),
                "amount_money": {"amount": index + 1, "currency": "USD"},
                "autocomplete": true,
                "location_id": location_id,
                "note": "Square Protect opt-in live test",
                "reference_id": format!("spi-{}", Uuid::new_v4().simple()),
            }))
            .send()
            .await
            .expect("Square payment request failed");
        let status = response.status();
        let body: Value = response
            .json()
            .await
            .expect("Square payment response was not JSON");
        assert!(
            status.is_success(),
            "Square payment creation failed: {body}"
        );
        created.push(
            body.get("payment")
                .cloned()
                .expect("Square response omitted the payment"),
        );
    }

    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(temp.path()).unwrap();
    let sync = SyncEngine::new(store.clone());
    for transaction in &created {
        assert!(sync.ingest_payment(transaction).await.unwrap());
    }
    let (transactions, _) = store
        .list_transactions_page(50, 0, None, "", "COMPLETED")
        .unwrap();
    assert_eq!(transactions.len(), 10);
    assert_eq!(
        transactions
            .iter()
            .map(|transaction| transaction.id.as_str())
            .collect::<HashSet<_>>()
            .len(),
        10
    );
    for key in [
        "square.access_token",
        "protect.host",
        "protect.username",
        "protect.password",
    ] {
        assert_eq!(store.get_setting(key).unwrap(), None);
    }
}

#[tokio::test]
#[ignore = "contacts a live Protect console and requires credentials"]
async fn configured_protect_camera_motion_matches_a_transaction() {
    let camera = configured_camera().await;
    let camera_id = camera.get("id").and_then(Value::as_str).unwrap();
    let camera_name = camera.get("name").and_then(Value::as_str).unwrap();
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(temp.path()).unwrap();
    let (_, token) = store
        .configure_motion(camera_id, camera_name, 15, 30, 1, true)
        .unwrap();
    let token = token.unwrap();
    let timestamp = now_millis();
    let app = build_router(app_state(store.clone(), temp.path().to_owned()));

    let response = app
        .oneshot(motion_request(&token, camera_id, timestamp))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    store
        .replace_camera_mappings(&[CameraMappingEntry {
            location_id: "LIVE_TEST_LOCATION".into(),
            device_id: String::new(),
            device_name: String::new(),
            camera_id: camera_id.into(),
            camera_name: camera_name.into(),
        }])
        .unwrap();
    store
        .upsert_payment(&payment(
            "LIVE_TEST_MATCHED_PAYMENT",
            "LIVE_TEST_LOCATION",
            timestamp + 500,
        ))
        .unwrap();

    let alerts = store.motion_alerts(50, true, timestamp + 31_000).unwrap();
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].state, "matched");
    assert_eq!(
        alerts[0].matched_transaction_id.as_deref(),
        Some("LIVE_TEST_MATCHED_PAYMENT")
    );
}

#[tokio::test]
#[ignore = "contacts a live Protect console and requires credentials"]
async fn configured_protect_camera_motion_without_a_transaction_is_flagged() {
    let camera = configured_camera().await;
    let camera_id = camera.get("id").and_then(Value::as_str).unwrap();
    let camera_name = camera.get("name").and_then(Value::as_str).unwrap();
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(temp.path()).unwrap();
    let (_, token) = store
        .configure_motion(camera_id, camera_name, 15, 1, 1, true)
        .unwrap();
    let token = token.unwrap();
    let timestamp = now_millis();
    let app = build_router(app_state(store.clone(), temp.path().to_owned()));

    let response = app
        .oneshot(motion_request(&token, camera_id, timestamp))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let alerts = store.motion_alerts(50, false, timestamp + 5_000).unwrap();
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].state, "flagged");
    assert!(alerts[0].matched_transaction_id.is_none());
}
