use crate::storage::read_osint_keys;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::{Duration, Instant};

const VT_MIN_INTERVAL: Duration = Duration::from_millis(15_000);
/// Short cooldown after 429 so another key is preferred, then this one can return.
const VT_COOLDOWN_429: Duration = Duration::from_secs(25);
const VT_COOLDOWN_AUTH: Duration = Duration::from_secs(24 * 60 * 60);
const VT_COOLDOWN_TIMEOUT: Duration = Duration::from_secs(15);
const ABUSE_MIN_INTERVAL: Duration = Duration::from_millis(2_000);

/// Per-key last-use timestamps so multiple API keys can run in parallel.
static VT_KEY_LAST: std::sync::OnceLock<Mutex<HashMap<String, Instant>>> = std::sync::OnceLock::new();
/// Keys unavailable until Instant (quota / auth failures).
static VT_KEY_COOLDOWN: std::sync::OnceLock<Mutex<HashMap<String, Instant>>> =
    std::sync::OnceLock::new();
static ABUSE_LAST: Mutex<Option<Instant>> = Mutex::new(None);
static HTTP: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();

fn vt_key_last() -> &'static Mutex<HashMap<String, Instant>> {
    VT_KEY_LAST.get_or_init(|| Mutex::new(HashMap::new()))
}

fn vt_key_cooldown() -> &'static Mutex<HashMap<String, Instant>> {
    VT_KEY_COOLDOWN.get_or_init(|| Mutex::new(HashMap::new()))
}

fn http_client() -> &'static reqwest::Client {
    HTTP.get_or_init(|| {
        reqwest::Client::builder()
            .user_agent("csv-vt-scanner/1.0")
            .connect_timeout(Duration::from_secs(8))
            .timeout(Duration::from_secs(15))
            .pool_max_idle_per_host(4)
            .build()
            .expect("client HTTP")
    })
}

async fn throttle(slot: &Mutex<Option<Instant>>, min_interval: Duration) {
    let wait = {
        let last = slot.lock().unwrap_or_else(|e| e.into_inner());
        last.and_then(|t| min_interval.checked_sub(t.elapsed()))
    };
    if let Some(delay) = wait {
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
    }
    *slot.lock().unwrap_or_else(|e| e.into_inner()) = Some(Instant::now());
}

fn set_key_cooldown(api_key: &str, duration: Duration) {
    let until = Instant::now() + duration;
    let mut map = vt_key_cooldown().lock().unwrap_or_else(|e| e.into_inner());
    map.insert(api_key.to_string(), until);
}

fn key_is_cooled(api_key: &str) -> bool {
    let map = vt_key_cooldown().lock().unwrap_or_else(|e| e.into_inner());
    match map.get(api_key) {
        Some(until) => Instant::now() < *until,
        None => false,
    }
}

/// Claim the VT key that will be ready soonest (skips cooled keys).
async fn acquire_vt_key(keys: &[String]) -> Result<String, String> {
    if keys.is_empty() {
        return Err("Chiave VirusTotal non configurata.".to_string());
    }
    loop {
        let decision = {
            let mut map = vt_key_last().lock().unwrap_or_else(|e| e.into_inner());
            let cool = vt_key_cooldown().lock().unwrap_or_else(|e| e.into_inner());
            let now = Instant::now();
            let mut best: Option<(usize, Duration)> = None;
            for (i, key) in keys.iter().enumerate() {
                if cool.get(key).is_some_and(|until| now < *until) {
                    continue;
                }
                let wait = match map.get(key) {
                    Some(last) => VT_MIN_INTERVAL.checked_sub(last.elapsed()).unwrap_or_default(),
                    None => Duration::ZERO,
                };
                match best {
                    None => best = Some((i, wait)),
                    Some((_, best_wait)) if wait < best_wait => best = Some((i, wait)),
                    Some((best_i, best_wait)) if wait == best_wait && i < best_i => {
                        best = Some((i, wait));
                    }
                    _ => {}
                }
            }
            match best {
                None => {
                    // All keys cooled: wait until soonest cooldown expires.
                    let mut soonest = Duration::from_secs(60);
                    for key in keys {
                        if let Some(until) = cool.get(key) {
                            if *until > now {
                                soonest = soonest.min(*until - now);
                            }
                        }
                    }
                    Ok::<(Option<String>, Duration), String>((None, soonest))
                }
                Some((idx, wait)) if wait.is_zero() => {
                    let key = keys[idx].clone();
                    map.insert(key.clone(), now);
                    Ok((Some(key), Duration::ZERO))
                }
                Some((_, wait)) => Ok((None, wait)),
            }
        }?;

        match decision {
            (Some(key), _) => return Ok(key),
            (None, wait) => {
                let sleep_for = if wait.is_zero() {
                    Duration::from_millis(200)
                } else {
                    wait.min(Duration::from_secs(30))
                };
                tokio::time::sleep(sleep_for).await;
            }
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VtLookupRequest {
    pub kind: String,
    pub value: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AbuseLookupRequest {
    pub ip: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VtLookupResult {
    pub status: String,
    pub summary: String,
    pub detection_ratio: Option<String>,
    pub malicious: Option<u64>,
    pub total: Option<u64>,
    pub country: Option<String>,
    pub as_owner: Option<String>,
    pub permalink: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AbuseLookupResult {
    pub status: String,
    pub summary: String,
    pub abuse_confidence_score: Option<u64>,
    pub total_reports: Option<u64>,
    pub country_code: Option<String>,
    pub isp: Option<String>,
    pub permalink: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VtKeyPoolStatus {
    pub total: u32,
    pub active: u32,
    pub cooled: u32,
}

fn vt_url_id(url: &str) -> String {
    URL_SAFE_NO_PAD.encode(url.as_bytes())
}

fn vt_endpoint(kind: &str, value: &str) -> Result<(String, String), String> {
    let v = value.trim();
    if v.is_empty() {
        return Err("Valore IOC vuoto.".to_string());
    }
    match kind {
        "ip" => Ok((
            format!("https://www.virustotal.com/api/v3/ip_addresses/{v}"),
            format!("https://www.virustotal.com/gui/ip-address/{v}"),
        )),
        "hash_sha256" | "hash_sha1" | "hash_md5" | "hash" => Ok((
            format!("https://www.virustotal.com/api/v3/files/{v}"),
            format!("https://www.virustotal.com/gui/file/{v}"),
        )),
        "domain" => Ok((
            format!("https://www.virustotal.com/api/v3/domains/{v}"),
            format!("https://www.virustotal.com/gui/domain/{v}"),
        )),
        "url" => {
            let id = vt_url_id(v);
            Ok((
                format!("https://www.virustotal.com/api/v3/urls/{id}"),
                format!("https://www.virustotal.com/gui/url/{id}"),
            ))
        }
        _ => Err(format!("Tipo VirusTotal non supportato: {kind}")),
    }
}

fn stats_counts(stats: &Value) -> (u64, u64) {
    fn num(stats: &Value, key: &str) -> u64 {
        stats
            .get(key)
            .and_then(|v| v.as_u64().or_else(|| v.as_i64().and_then(|n| u64::try_from(n).ok())))
            .unwrap_or(0)
    }
    let malicious = num(stats, "malicious");
    let total: u64 = ["malicious", "suspicious", "undetected", "harmless", "timeout"]
        .iter()
        .map(|k| num(stats, k))
        .sum();
    (malicious, if total == 0 { 1 } else { total })
}

fn json_string(value: Option<&Value>) -> Option<String> {
    value.and_then(|v| v.as_str().map(str::to_string))
}

async fn vt_get_once(url: &str, api_key: &str) -> Result<(u16, Value), String> {
    let response = http_client()
        .get(url)
        .header("x-apikey", api_key)
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| format!("Errore di rete VirusTotal: {e}"))?;
    let status = response.status().as_u16();
    let body = response
        .json::<Value>()
        .await
        .unwrap_or_else(|_| Value::Object(serde_json::Map::new()));
    Ok((status, body))
}

fn parse_vt_success(body: &Value, permalink: String) -> VtLookupResult {
    let attrs = body
        .pointer("/data/attributes")
        .cloned()
        .unwrap_or(Value::Null);
    let stats = attrs
        .get("last_analysis_stats")
        .cloned()
        .unwrap_or(Value::Null);
    let (malicious, total) = stats_counts(&stats);
    let sha256 = json_string(attrs.get("sha256"));
    let permalink = sha256
        .as_ref()
        .map(|h| format!("https://www.virustotal.com/gui/file/{h}"))
        .unwrap_or(permalink);

    VtLookupResult {
        status: "success".into(),
        summary: format!("VT {malicious}/{total}"),
        detection_ratio: Some(format!("{malicious}/{total}")),
        malicious: Some(malicious),
        total: Some(total),
        country: json_string(attrs.get("country")),
        as_owner: json_string(attrs.get("as_owner")),
        permalink: Some(permalink),
        error: None,
    }
}

#[tauri::command]
pub fn vt_key_pool_status() -> Result<VtKeyPoolStatus, String> {
    let keys = read_osint_keys()?;
    let cool = vt_key_cooldown().lock().unwrap_or_else(|e| e.into_inner());
    let now = Instant::now();
    let mut active = 0u32;
    let mut cooled = 0u32;
    for key in &keys.vt_api_keys {
        if cool.get(key).is_some_and(|until| now < *until) {
            cooled += 1;
        } else {
            active += 1;
        }
    }
    Ok(VtKeyPoolStatus {
        total: keys.vt_api_keys.len() as u32,
        active,
        cooled,
    })
}

#[tauri::command]
pub async fn vt_lookup(payload: VtLookupRequest) -> Result<VtLookupResult, String> {
    let keys = read_osint_keys()?;
    if keys.vt_api_keys.is_empty() {
        return Err("Chiave VirusTotal non configurata.".to_string());
    }
    let (url, permalink) = vt_endpoint(&payload.kind, &payload.value)?;
    let mut tried: HashSet<String> = HashSet::new();
    let mut last_error: Option<String> = None;
    let max_rounds = keys.vt_api_keys.len().saturating_mul(2).max(2);
    let mut rounds = 0usize;

    while tried.len() < keys.vt_api_keys.len() && rounds < max_rounds {
        rounds += 1;
        let candidates: Vec<String> = keys
            .vt_api_keys
            .iter()
            .filter(|k| !tried.contains(*k) && !key_is_cooled(k))
            .cloned()
            .collect();

        let api_key = if candidates.is_empty() {
            let remaining: Vec<String> = keys
                .vt_api_keys
                .iter()
                .filter(|k| !tried.contains(*k))
                .cloned()
                .collect();
            if remaining.is_empty() {
                break;
            }
            // Bounded wait for cooldown instead of potentially long acquire loop.
            tokio::time::sleep(Duration::from_secs(2)).await;
            match acquire_vt_key(&remaining).await {
                Ok(k) => k,
                Err(e) => {
                    last_error = Some(e);
                    break;
                }
            }
        } else {
            acquire_vt_key(&candidates).await?
        };

        match try_vt_with_key(&url, &permalink, &api_key, &mut tried, &mut last_error).await {
            Ok(Some(result)) => return Ok(result),
            Ok(None) => continue,
            Err(e) => {
                // Treat network/timeout as key failure → cool briefly → next key.
                set_key_cooldown(&api_key, VT_COOLDOWN_TIMEOUT);
                tried.insert(api_key);
                last_error = Some(e);
                continue;
            }
        }
    }

    Ok(VtLookupResult {
        status: "error".into(),
        summary: "Tutte le chiavi VirusTotal in errore o in cooldown".into(),
        detection_ratio: None,
        malicious: None,
        total: None,
        country: None,
        as_owner: None,
        permalink: Some(permalink),
        error: last_error.or_else(|| Some("NoAvailableKeys".into())),
    })
}

/// Returns Ok(Some(result)) on terminal success/404/non-retryable error,
/// Ok(None) to retry with another key, Err on hard failure.
async fn try_vt_with_key(
    url: &str,
    permalink: &str,
    api_key: &str,
    tried: &mut HashSet<String>,
    last_error: &mut Option<String>,
) -> Result<Option<VtLookupResult>, String> {
    let (status, body) = vt_get_once(url, api_key).await?;

    if status == 404 {
        return Ok(Some(VtLookupResult {
            status: "not_found".into(),
            summary: "IOC non presente in VirusTotal".into(),
            detection_ratio: None,
            malicious: None,
            total: None,
            country: None,
            as_owner: None,
            permalink: Some(permalink.to_string()),
            error: None,
        }));
    }

    if status == 429 {
        set_key_cooldown(api_key, VT_COOLDOWN_429);
        tried.insert(api_key.to_string());
        *last_error = Some("TooManyRequests".into());
        return Ok(None);
    }

    if status == 401 || status == 403 {
        set_key_cooldown(api_key, VT_COOLDOWN_AUTH);
        tried.insert(api_key.to_string());
        *last_error = Some(format!("{status}: Unauthorized"));
        return Ok(None);
    }

    if status >= 400 {
        let message = body
            .pointer("/error/message")
            .and_then(Value::as_str)
            .unwrap_or("Errore API VirusTotal");
        // Other 4xx: try another key once; mark this one briefly cooled.
        if status == 400 || status == 402 || status >= 500 {
            set_key_cooldown(api_key, VT_COOLDOWN_429);
            tried.insert(api_key.to_string());
            *last_error = Some(format!("{status}: {message}"));
            return Ok(None);
        }
        return Ok(Some(VtLookupResult {
            status: "error".into(),
            summary: "Errore API VirusTotal".into(),
            detection_ratio: None,
            malicious: None,
            total: None,
            country: None,
            as_owner: None,
            permalink: Some(permalink.to_string()),
            error: Some(format!("{status}: {message}")),
        }));
    }

    Ok(Some(parse_vt_success(&body, permalink.to_string())))
}

#[tauri::command]
pub async fn abuseipdb_lookup(payload: AbuseLookupRequest) -> Result<AbuseLookupResult, String> {
    let keys = read_osint_keys()?;
    let api_key = keys.abuse_ipdb_api_key.trim();
    if api_key.is_empty() {
        return Err("Chiave AbuseIPDB non configurata.".to_string());
    }
    let ip = payload.ip.trim();
    if ip.is_empty() {
        return Err("IP vuoto.".to_string());
    }

    throttle(&ABUSE_LAST, ABUSE_MIN_INTERVAL).await;
    let url = format!("https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90");
    let response = http_client()
        .get(&url)
        .header("Key", api_key)
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| format!("Errore di rete AbuseIPDB: {e}"))?;
    let status = response.status().as_u16();
    let body = response
        .json::<Value>()
        .await
        .unwrap_or_else(|_| Value::Object(serde_json::Map::new()));

    if status >= 400 {
        let message = body
            .pointer("/errors/0/detail")
            .and_then(Value::as_str)
            .unwrap_or("Errore API AbuseIPDB");
        return Ok(AbuseLookupResult {
            status: "error".into(),
            summary: "Errore API AbuseIPDB".into(),
            abuse_confidence_score: None,
            total_reports: None,
            country_code: None,
            isp: None,
            permalink: Some(format!("https://www.abuseipdb.com/check/{ip}")),
            error: Some(format!("{status}: {message}")),
        });
    }
    if body.get("data").is_none() {
        return Ok(AbuseLookupResult {
            status: "not_found".into(),
            summary: "IP non presente in AbuseIPDB".into(),
            abuse_confidence_score: None,
            total_reports: None,
            country_code: None,
            isp: None,
            permalink: Some(format!("https://www.abuseipdb.com/check/{ip}")),
            error: None,
        });
    }

    let data = body.get("data").cloned().unwrap_or(Value::Null);
    let score = data
        .get("abuseConfidenceScore")
        .and_then(|v| v.as_u64().or_else(|| v.as_i64().and_then(|n| u64::try_from(n).ok())))
        .unwrap_or(0);
    let reports = data
        .get("totalReports")
        .and_then(|v| v.as_u64().or_else(|| v.as_i64().and_then(|n| u64::try_from(n).ok())))
        .unwrap_or(0);

    Ok(AbuseLookupResult {
        status: "success".into(),
        summary: format!("AbuseIPDB {score}% ({reports} segnalazioni)"),
        abuse_confidence_score: Some(score),
        total_reports: Some(reports),
        country_code: json_string(data.get("countryCode")),
        isp: json_string(data.get("isp")),
        permalink: Some(format!("https://www.abuseipdb.com/check/{ip}")),
        error: None,
    })
}

fn url_allowed(url: &str) -> bool {
    url.starts_with("https://www.virustotal.com/") || url.starts_with("https://www.abuseipdb.com/")
}

#[tauri::command]
pub fn open_external_url(url: String) -> Result<(), String> {
    if !url_allowed(&url) {
        return Err("URL non consentito.".to_string());
    }
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("cmd")
            .args(["/C", "start", "", &url])
            .spawn()
            .map_err(|e| e.to_string())?;
        return Ok(());
    }
    #[cfg(not(target_os = "windows"))]
    {
        std::process::Command::new("xdg-open")
            .arg(&url)
            .spawn()
            .map_err(|e| e.to_string())?;
        Ok(())
    }
}
