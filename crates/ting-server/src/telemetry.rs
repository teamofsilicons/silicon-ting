use crate::{
    Shared,
    error::{Error, Result},
    validation as v,
};
use serde_json::{Value, json};
use std::{env, sync::OnceLock, time::Duration};

pub async fn ingest(app: &Shared, body: Value) -> Result<Value> {
    v::fields(&body, &["table", "events"], &["table", "events"])?;
    let table = v::string(&body, "table", 100)?;
    let key_name = match table {
        "tingclidaemon" => "TING_TELEMETRY_CLI_KEY",
        "tingfrontendanalytics" => "TING_TELEMETRY_ANALYTICS_KEY",
        "tingfrontendevents" => "TING_TELEMETRY_EVENTS_KEY",
        _ => return Err(Error::invalid("This telemetry table is not available.")),
    };
    let key = env::var(key_name)
        .ok()
        .filter(|k| !k.is_empty())
        .ok_or_else(|| Error::unavailable("Telemetry ingestion is not configured."))?;
    let events = body["events"]
        .as_array()
        .filter(|a| !a.is_empty() && a.len() <= 40)
        .ok_or_else(|| Error::invalid("A telemetry batch requires 1–40 events."))?;
    let mut records = vec![];
    for event in events {
        v::fields(
            event,
            &["id", "type", "data", "metadata"],
            &["type", "data"],
        )?;
        let typ = v::string(event, "type", 200)?;
        let id = match event.get("id") {
            Some(_) => v::string(event, "id", 200)?.to_owned(),
            None => uuid::Uuid::new_v4().to_string(),
        };
        if event.get("metadata").is_some_and(|m| !m.is_object()) {
            return Err(Error::invalid("Telemetry metadata must be an object."));
        }
        records.push(json!({"key":key,"metadata":{"record_id":id,"table_id":table,"event_ts_ms":chrono::Utc::now().timestamp_millis()},"record":{"type":typ,"data":event["data"],"metadata":event.get("metadata").cloned().unwrap_or(json!({}))}}));
    }
    static HTTP: OnceLock<reqwest::Client> = OnceLock::new();
    let http = HTTP.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("valid HTTP client")
    });
    let res = http
        .post(format!(
            "{}/api/ingest",
            app.config.spacestation_url.trim_end_matches('/')
        ))
        .json(&json!({"batch_id":uuid::Uuid::new_v4().to_string(),"records":records}))
        .send()
        .await
        .map_err(|_| Error::unavailable("Telemetry storage could not be reached."))?;
    if !res.status().is_success() {
        return Err(Error::unavailable(
            "Telemetry storage did not accept the batch.",
        ));
    }
    let ack: Value = res
        .json()
        .await
        .map_err(|_| Error::unavailable("Telemetry storage returned an invalid acknowledgment."))?;
    if ack
        .get("rejected")
        .and_then(Value::as_array)
        .is_some_and(|items| items.iter().any(|item| item["code"] != "duplicate"))
    {
        return Err(Error::unavailable(
            "Telemetry storage rejected one or more events.",
        ));
    }
    Ok(json!({"accepted":true}))
}
