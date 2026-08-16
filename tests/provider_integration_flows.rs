use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
};

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{Request, StatusCode, header},
};
use serde_json::json;
use square_unifi_protect::{
    AppState, Config, DEFAULT_PORT, Store, build_router,
    models::{CameraMappingEntry, PaymentFacts},
    store::now_millis,
    sync::SyncEngine,
};
use tower::ServiceExt;

const CAMERA_ID: &str = "cam1aaaaaaaaaaaaaaaaaaaa";
const LOCATION_ID: &str = "SANDBOX_LOCATION";

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

fn motion_request(token: &str, timestamp: i64) -> Request<Body> {
    let payload = json!({
        "timestamp": timestamp,
        "alarm": {
            "name": "Test camera register motion",
            "conditions": [{"condition": {"source": "motion"}}],
            "triggers": [{"key": "motion", "device": CAMERA_ID}],
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
        41_000,
    )));
    request
}

fn mapped_payment(id: &str, timestamp: i64) -> PaymentFacts {
    PaymentFacts {
        id: id.into(),
        created_at: "2026-08-09T08:00:00.000-07:00".into(),
        ts_ms: timestamp,
        updated_at: "2026-08-09T08:00:00.000-07:00".into(),
        updated_ts_ms: timestamp,
        amount: 99,
        currency: "USD".into(),
        status: "COMPLETED".into(),
        location_id: LOCATION_ID.into(),
        ..PaymentFacts::default()
    }
}

#[tokio::test]
async fn ten_square_transactions_ingest_without_provider_credentials() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(temp.path()).unwrap();
    let sync = SyncEngine::new(store.clone());

    for index in 0..10 {
        let second = index + 10;
        let payment = json!({
            "id": format!("SANDBOX_PAYMENT_{index:02}"),
            "created_at": format!("2026-08-09T15:00:{second:02}.000Z"),
            "updated_at": format!("2026-08-09T15:00:{second:02}.000Z"),
            "amount_money": {"amount": 90 + index, "currency": "USD"},
            "status": "COMPLETED",
            "location_id": LOCATION_ID,
        });
        assert!(sync.ingest_payment(&payment).await.unwrap());
    }

    let (transactions, _) = store
        .list_transactions_page(50, 0, None, "SANDBOX_PAYMENT", "COMPLETED")
        .unwrap();
    assert_eq!(transactions.len(), 10);
    assert!(transactions.iter().all(|payment| payment.amount <= 99));
    assert_eq!(
        transactions
            .iter()
            .map(|payment| payment.id.as_str())
            .collect::<std::collections::HashSet<_>>()
            .len(),
        10
    );
    for credential in [
        "square.access_token",
        "protect.host",
        "protect.username",
        "protect.password",
    ] {
        assert_eq!(store.get_setting(credential).unwrap(), None);
    }
}

#[tokio::test]
async fn protect_motion_webhook_matches_a_following_transaction() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(temp.path()).unwrap();
    let (_, token) = store
        .configure_motion(CAMERA_ID, "Checkout Camera", 15, 30, 1, true)
        .unwrap();
    let token = token.unwrap();
    let event_timestamp = now_millis();
    let app = build_router(app_state(store.clone(), temp.path().to_owned()));

    let response = app
        .oneshot(motion_request(&token, event_timestamp))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        store.motion_alerts(50, true, event_timestamp).unwrap()[0].state,
        "pending"
    );

    store
        .replace_camera_mappings(&[CameraMappingEntry {
            location_id: LOCATION_ID.into(),
            device_id: String::new(),
            device_name: String::new(),
            camera_id: CAMERA_ID.into(),
            camera_name: "Checkout Camera".into(),
        }])
        .unwrap();
    store
        .upsert_payment(&mapped_payment(
            "SANDBOX_MATCHED_PAYMENT",
            event_timestamp + 500,
        ))
        .unwrap();

    let alerts = store
        .motion_alerts(50, true, event_timestamp + 31_000)
        .unwrap();
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].state, "matched");
    assert_eq!(
        alerts[0].matched_transaction_id.as_deref(),
        Some("SANDBOX_MATCHED_PAYMENT")
    );
    assert_eq!(alerts[0].transaction_delta_ms, Some(500));
}

#[tokio::test]
async fn protect_motion_without_a_transaction_becomes_flagged_after_grace() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(temp.path()).unwrap();
    let (_, token) = store
        .configure_motion(CAMERA_ID, "Checkout Camera", 15, 1, 1, true)
        .unwrap();
    let token = token.unwrap();
    let event_timestamp = now_millis();
    let app = build_router(app_state(store.clone(), temp.path().to_owned()));

    let response = app
        .oneshot(motion_request(&token, event_timestamp))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        store.motion_alerts(50, true, event_timestamp).unwrap()[0].state,
        "pending"
    );

    let alerts = store
        .motion_alerts(50, false, event_timestamp + 5_000)
        .unwrap();
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].state, "flagged");
    assert!(alerts[0].matched_transaction_id.is_none());
    assert_eq!(
        store.motion_summary(event_timestamp + 5_000).unwrap(),
        json!({"matched": 0, "pending": 0, "flagged": 1})
    );
}
