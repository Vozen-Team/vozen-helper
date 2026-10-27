//! Module registry for Core, Studio, Security, Support, Events, Community,
//! Automate and Insights. Feature handlers are added behind these boundaries.

pub mod temp_creator;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use helper_contracts::{EntitlementSnapshot, Plan};
use helper_core::Capability;
use helper_store::Store;
use hmac::{Hmac, Mac};
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use quick_xml::{Reader, escape::unescape, events::Event};
use rand::RngCore;
use reqwest::Client;
use ring::{
    aead::{self, Aad, LessSafeKey, Nonce, UnboundKey},
    rand::{SecureRandom, SystemRandom},
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use sha3::Keccak256;
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{sync::Mutex as AsyncMutex, task::JoinHandle};
use url::Url;

/// Shared API/gateway gate. Sandbox permits only creator OAuth; the legacy
/// process-wide token remains production-approval-only.
pub fn tiktok_runtime_allowed(
    approved: bool,
    sandbox: bool,
    oauth_ready: bool,
    fallback_ready: bool,
) -> bool {
    (approved && fallback_ready) || ((approved || sandbox) && oauth_ready)
}

/// Reads a boolean provider gate using the same tolerant representation in
/// every runtime boundary. Secrets and other values are never returned.
pub fn env_flag_value_is_true(value: Option<&str>) -> bool {
    value.is_some_and(|value| value.trim().eq_ignore_ascii_case("true"))
}

/// Read one environment-backed approval flag without leaking its value.
pub fn env_flag_is_true(name: &str) -> bool {
    env_flag_value_is_true(std::env::var(name).ok().as_deref())
}

/// Read a primary flag and only fall back to aliases when the primary is not
/// present. A present `false` value must not be overridden by a legacy alias.
pub fn first_env_flag_is_true(names: &[&str]) -> bool {
    names
        .iter()
        .find_map(|name| std::env::var(name).ok())
        .is_some_and(|value| env_flag_value_is_true(Some(&value)))
}

/// Small, server-side client for the official YouTube Data API.
///
/// The API key is read only from the process environment. It is never part
/// of a response, log line, or panel payload. The client is intentionally
/// limited to public channel metadata and a channel's official uploads
/// playlist. Alert polling and Discord delivery use the same boundary.
#[derive(Clone)]
pub struct YouTubeClient {
    api_key: Arc<str>,
    http: Client,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct YouTubeChannel {
    pub id: String,
    pub title: String,
    pub description: String,
    pub custom_url: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct YouTubeVideo {
    pub id: String,
    pub title: String,
    pub description: String,
    pub url: String,
    pub published_at: String,
    pub channel_title: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct YouTubeSearchResult {
    pub id: String,
    pub title: String,
    pub description: String,
    pub url: String,
    pub channel_title: String,
}

/// Server-side client for public RSS/Atom feeds. URLs are structurally
/// validated, resolved away from private/link-local addresses and fetched
/// without following redirects so this cannot become an SSRF proxy.
#[derive(Clone)]
pub struct RssClient;

#[derive(Debug, Clone, serde::Serialize)]
pub struct RssItem {
    pub id: String,
    pub title: String,
    pub description: String,
    pub url: String,
    pub published_at: String,
    pub feed_title: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RssFeed {
    pub url: String,
    pub title: String,
    pub latest: Option<RssItem>,
}

/// Render an RSS/Atom alert with the same bounded substitutions used by the
/// Discord worker and the API test-delivery endpoint. Provider fields are
/// treated as plain text and the result is always kept within Discord's
/// 2,000-character message limit.
pub fn format_rss_message(template: &str, mention: &str, item: &RssItem) -> String {
    let rendered = template
        .replace("{feed}", &item.feed_title)
        .replace("{title}", &item.title)
        .replace("{url}", &item.url)
        .replace("{published_at}", &item.published_at)
        .replace("{description}", &item.description);
    let rendered = if mention.is_empty() {
        rendered
    } else {
        format!("{mention} {rendered}")
    };
    rendered.chars().take(2_000).collect()
}

/// Render a YouTube alert with the same bounded substitutions used by the
/// Discord worker and the API test-delivery endpoint. Provider fields are
/// treated as plain text and the result stays within Discord's message limit.
pub fn format_youtube_message(
    template: &str,
    mention: &str,
    video: &YouTubeVideo,
    channel_id: &str,
) -> String {
    let channel = if video.channel_title.is_empty() {
        channel_id
    } else {
        video.channel_title.as_str()
    };
    let rendered = template
        .replace("{title}", &video.title)
        .replace("{url}", &video.url)
        .replace("{channel}", channel)
        .replace("{published_at}", &video.published_at)
        .replace("{description}", &video.description);
    let rendered = if mention.is_empty() {
        rendered
    } else {
        format!("{mention} {rendered}")
    };
    rendered.chars().take(2_000).collect()
}

/// Render a Twitch live alert with bounded substitutions shared by the
/// EventSub worker and the API delivery probe.
pub fn format_twitch_message(
    template: &str,
    mention: &str,
    login: &str,
    stream_id: &str,
    started_at: &str,
) -> String {
    let url = format!("https://twitch.tv/{login}");
    let rendered = template
        .replace("{broadcaster}", login)
        .replace("{login}", login)
        .replace("{stream_id}", stream_id)
        .replace("{started_at}", started_at)
        .replace("{url}", &url);
    let rendered = if mention.is_empty() {
        rendered
    } else {
        format!("{mention} {rendered}")
    };
    rendered.chars().take(2_000).collect()
}

/// Client for the public Bluesky AppView API. Alerts only read public posts;
/// no account token is required. The runtime polls the author's feed with a
/// bounded page size and stores the last URI for idempotent delivery.
#[derive(Clone)]
pub struct BlueskyClient {
    http: Client,
}

/// Official TikTok Display API client. Access is limited to videos from the
/// creator who granted the Display API token; the runtime never scrapes
/// TikTok pages or accepts arbitrary profile URLs.
#[derive(Clone)]
pub struct TikTokClient {
    access_token: Arc<str>,
    base_url: Arc<str>,
    http: Client,
}

/// Official Meta Graph API client for Instagram professional accounts.
///
/// Only media belonging to the explicitly authorised Instagram user is read;
/// the access token and account id are process secrets and never leave the
/// server.  The client deliberately does not accept profile URLs or scrape
/// Instagram pages.
#[derive(Clone)]
pub struct InstagramClient {
    access_token: Arc<str>,
    user_id: Arc<str>,
    base_url: Arc<str>,
    http: Client,
}

/// Official Kick public API client. It only reads the documented channel
/// endpoint and never scrapes kick.com pages. A token is required by the
/// current API and is kept exclusively in the process environment.
#[derive(Clone)]
pub struct KickClient {
    access_token: Arc<str>,
    base_url: Arc<str>,
    http: Client,
}

/// Minimal Stripe Connect boundary for server monetization. It verifies
/// signed webhook envelopes and keeps all Stripe credentials server-side;
/// card data never enters the Helper API or SQLite.
#[derive(Clone)]
pub struct StripeConnectClient {
    secret_key: Arc<str>,
    webhook_secret: Arc<str>,
}

/// Verifies EIP-4361 messages without ever accepting a private key. The
/// domain, URI, version and nonce are checked by the caller before a role
/// mutation is queued. Signature recovery uses secp256k1 + Ethereum Keccak;
/// SHA3-256 is deliberately not used because its padding differs.
#[derive(Clone)]
pub struct SiweVerifier {
    domain: Arc<str>,
    uri: Arc<str>,
    session_secret: Arc<str>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SiweClaims {
    pub address: String,
    pub domain: String,
    pub uri: String,
    pub chain_id: u64,
    pub nonce: String,
    pub issued_at: String,
    pub expiration_time: Option<String>,
}

/// Bounded, read-only Ethereum JSON-RPC client used by wallet gating. It
/// supports only the standard `balanceOf` calls and never signs or submits a
/// transaction. RPC URLs are selected by chain from the server environment.
#[derive(Clone)]
pub struct EthereumRpcClient {
    chain: Arc<str>,
    endpoint: Arc<str>,
    http: Client,
}

impl EthereumRpcClient {
    pub fn from_env(chain: &str) -> Option<Self> {
        let variable = match chain {
            "ethereum" => "ETHEREUM_RPC_URL",
            "polygon" => "POLYGON_RPC_URL",
            "arbitrum" => "ARBITRUM_RPC_URL",
            "base" => "BASE_RPC_URL",
            _ => return None,
        };
        Self::new(chain, std::env::var(variable).ok()?)
    }

    pub fn new(chain: &str, endpoint: impl Into<String>) -> Option<Self> {
        if !matches!(chain, "ethereum" | "polygon" | "arbitrum" | "base") {
            return None;
        }
        let endpoint = endpoint.into().trim().trim_end_matches('/').to_owned();
        let parsed = Url::parse(&endpoint).ok()?;
        if parsed.scheme() != "https" && parsed.host_str() != Some("localhost") {
            return None;
        }
        Some(Self {
            chain: Arc::from(chain.to_owned()),
            endpoint: Arc::from(endpoint),
            http: Client::builder()
                .timeout(Duration::from_secs(8))
                .user_agent("Vozen-Helper/1.0 (+https://vozen.org)")
                .build()
                .ok()?,
        })
    }

    pub fn chain(&self) -> &str {
        &self.chain
    }

    pub async fn token_balance(
        &self,
        contract: &str,
        wallet: &str,
        asset_type: &str,
        token_id: Option<&str>,
    ) -> anyhow::Result<u128> {
        if !is_eth_address(contract) || !is_eth_address(wallet) {
            anyhow::bail!("ethereum_address_invalid");
        }
        let wallet_word = format!(
            "{:0>64}",
            wallet.trim_start_matches("0x").to_ascii_lowercase()
        );
        let data = match asset_type {
            "erc20" | "erc721" => format!("0x70a08231{wallet_word}"),
            "erc1155" => {
                let token = token_id.ok_or_else(|| anyhow::anyhow!("token_id_required"))?;
                let token = parse_uint_hex_or_decimal(token)?;
                format!("0x00fdd58e{wallet_word}{token:0>64x}")
            }
            _ => anyhow::bail!("asset_type_invalid"),
        };
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_call",
            "params": [{"to": contract, "data": data}, "latest"]
        });
        let response = self
            .http
            .post(self.endpoint.as_ref())
            .json(&body)
            .send()
            .await?;
        if !response.status().is_success() {
            anyhow::bail!("rpc_http_error:{}", response.status());
        }
        let payload: serde_json::Value = bounded_provider_json(response).await?;
        if let Some(error) = payload.get("error") {
            anyhow::bail!(
                "rpc_error:{}",
                error
                    .get("message")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("unknown")
            );
        }
        let result = payload
            .get("result")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("rpc_result_missing"))?;
        parse_rpc_uint(result)
    }
}

fn parse_uint_hex_or_decimal(raw: &str) -> anyhow::Result<u128> {
    let value = raw.trim();
    if value.is_empty() || value.len() > 78 {
        anyhow::bail!("uint_invalid");
    }
    if let Some(hex_value) = value.strip_prefix("0x") {
        u128::from_str_radix(hex_value, 16).map_err(|_| anyhow::anyhow!("uint_invalid"))
    } else {
        value
            .parse::<u128>()
            .map_err(|_| anyhow::anyhow!("uint_invalid"))
    }
}

fn parse_rpc_uint(raw: &str) -> anyhow::Result<u128> {
    let value = raw.strip_prefix("0x").unwrap_or(raw);
    if value.is_empty() || value.len() > 32 {
        anyhow::bail!("rpc_balance_too_large");
    }
    u128::from_str_radix(value, 16).map_err(|_| anyhow::anyhow!("rpc_result_invalid"))
}

impl SiweVerifier {
    pub fn from_env() -> Option<Self> {
        Self::new(
            std::env::var("SIWE_DOMAIN").ok()?,
            std::env::var("SIWE_URI").ok()?,
            std::env::var("SIWE_SESSION_SECRET").ok()?,
        )
    }

    pub fn new(
        domain: impl Into<String>,
        uri: impl Into<String>,
        session_secret: impl Into<String>,
    ) -> Option<Self> {
        let domain = domain.into().trim().to_owned();
        let uri = uri.into().trim().to_owned();
        let session_secret = session_secret.into().trim().to_owned();
        if domain.is_empty()
            || domain.len() > 255
            || uri.is_empty()
            || uri.len() > 2_048
            || session_secret.len() < 32
            || session_secret.len() > 512
        {
            return None;
        }
        let parsed = Url::parse(&uri).ok()?;
        if parsed.scheme() != "https" && parsed.host_str() != Some("localhost") {
            return None;
        }
        Some(Self {
            domain: Arc::from(domain),
            uri: Arc::from(uri),
            session_secret: Arc::from(session_secret),
        })
    }

    pub fn is_configured(&self) -> bool {
        !self.domain.is_empty() && !self.uri.is_empty() && self.session_secret.len() >= 32
    }

    pub fn issue_nonce(&self) -> String {
        let mut bytes = [0_u8; 24];
        rand::rng().fill_bytes(&mut bytes);
        // EIP-4361 nonces are alphanumeric. Hex avoids '-'/'_' from a
        // URL-safe alphabet and therefore cannot be rejected by the parser.
        hex::encode(bytes)
    }

    pub fn expected_domain(&self) -> &str {
        &self.domain
    }

    pub fn expected_uri(&self) -> &str {
        &self.uri
    }

    pub fn verify(
        &self,
        message: &str,
        signature: &str,
        expected_nonce: &str,
        now: chrono::DateTime<Utc>,
    ) -> anyhow::Result<SiweClaims> {
        let claims = parse_siwe_message(message)?;
        if claims.domain != self.domain.as_ref() || claims.uri != self.uri.as_ref() {
            anyhow::bail!("siwe_domain_or_uri_mismatch");
        }
        if claims.nonce != expected_nonce || expected_nonce.len() < 8 {
            anyhow::bail!("siwe_nonce_mismatch");
        }
        let issued = chrono::DateTime::parse_from_rfc3339(&claims.issued_at)
            .map_err(|_| anyhow::anyhow!("siwe_invalid_issued_at"))?
            .with_timezone(&Utc);
        if issued > now + chrono::Duration::minutes(5)
            || issued < now - chrono::Duration::minutes(10)
        {
            anyhow::bail!("siwe_issued_at_out_of_window");
        }
        if let Some(expiration) = &claims.expiration_time {
            let expiry = chrono::DateTime::parse_from_rfc3339(expiration)
                .map_err(|_| anyhow::anyhow!("siwe_invalid_expiration"))?
                .with_timezone(&Utc);
            if expiry <= now {
                anyhow::bail!("siwe_expired");
            }
            if expiry > now + chrono::Duration::hours(24) {
                anyhow::bail!("siwe_expiration_too_long");
            }
        }
        let recovered = recover_eth_address(message, signature)?;
        if !recovered.eq_ignore_ascii_case(&claims.address) {
            anyhow::bail!("siwe_address_mismatch");
        }
        Ok(claims)
    }
}

fn parse_siwe_message(message: &str) -> anyhow::Result<SiweClaims> {
    if message.len() > 8_192 || !message.is_ascii() {
        anyhow::bail!("siwe_message_invalid");
    }
    let lines: Vec<&str> = message.lines().collect();
    if lines.len() < 8 || !lines[2].trim().is_empty() {
        anyhow::bail!("siwe_message_invalid");
    }
    let (domain, suffix) = lines[0]
        .split_once(" wants you to sign in with your Ethereum account:")
        .ok_or_else(|| anyhow::anyhow!("siwe_message_invalid"))?;
    if domain.trim().is_empty() || !suffix.is_empty() {
        anyhow::bail!("siwe_message_invalid");
    }
    let address = lines[1].trim().to_owned();
    if !is_eth_address(&address) {
        anyhow::bail!("siwe_address_invalid");
    }
    let mut fields = std::collections::HashMap::<&str, &str>::new();
    for line in lines.iter().skip(3) {
        if let Some((key, value)) = line.split_once(':') {
            fields.insert(key.trim(), value.trim());
        }
    }
    if fields.get("Version").copied() != Some("1") {
        anyhow::bail!("siwe_version_invalid");
    }
    let uri = fields
        .get("URI")
        .copied()
        .ok_or_else(|| anyhow::anyhow!("siwe_uri_missing"))?;
    let chain_id = fields
        .get("Chain ID")
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| anyhow::anyhow!("siwe_chain_id_invalid"))?;
    if chain_id == 0 {
        anyhow::bail!("siwe_chain_id_invalid");
    }
    let nonce = fields
        .get("Nonce")
        .copied()
        .ok_or_else(|| anyhow::anyhow!("siwe_nonce_missing"))?;
    if nonce.len() < 8
        || nonce.len() > 128
        || !nonce.bytes().all(|byte| byte.is_ascii_alphanumeric())
    {
        anyhow::bail!("siwe_nonce_invalid");
    }
    let issued_at = fields
        .get("Issued At")
        .copied()
        .ok_or_else(|| anyhow::anyhow!("siwe_issued_at_missing"))?;
    let expiration_time = fields.get("Expiration Time").copied().map(str::to_owned);
    Ok(SiweClaims {
        address,
        domain: domain.to_owned(),
        uri: uri.to_owned(),
        chain_id,
        nonce: nonce.to_owned(),
        issued_at: issued_at.to_owned(),
        expiration_time,
    })
}

fn is_eth_address(address: &str) -> bool {
    let body = address
        .strip_prefix("0x")
        .or_else(|| address.strip_prefix("0X"));
    body.is_some_and(|value| {
        value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
    })
}

fn recover_eth_address(message: &str, signature: &str) -> anyhow::Result<String> {
    let encoded = signature.strip_prefix("0x").unwrap_or(signature);
    let bytes = hex::decode(encoded).map_err(|_| anyhow::anyhow!("siwe_signature_invalid"))?;
    if bytes.len() != 65 {
        anyhow::bail!("siwe_signature_invalid");
    }
    let recovery = match bytes[64] {
        0 | 1 => bytes[64],
        27 | 28 => bytes[64] - 27,
        _ => anyhow::bail!("siwe_recovery_id_invalid"),
    };
    let signature =
        Signature::try_from(&bytes[..64]).map_err(|_| anyhow::anyhow!("siwe_signature_invalid"))?;
    // Recovery no longer verifies low-S in k256 0.14; preserve the previous rejection.
    if signature != signature.normalize_s() {
        anyhow::bail!("siwe_signature_invalid");
    }
    let recovery =
        RecoveryId::try_from(recovery).map_err(|_| anyhow::anyhow!("siwe_recovery_id_invalid"))?;
    let mut payload = format!("\x19Ethereum Signed Message:\n{}", message.len()).into_bytes();
    payload.extend_from_slice(message.as_bytes());
    let key = VerifyingKey::recover_from_prehash(&Keccak256::digest(payload), &signature, recovery)
        .map_err(|_| anyhow::anyhow!("siwe_signature_invalid"))?;
    Ok(eth_address_from_key(&key))
}

fn eth_address_from_key(key: &VerifyingKey) -> String {
    let point = key.to_sec1_point(false);
    let digest = Keccak256::digest(&point.as_bytes()[1..]);
    format!("0x{}", hex::encode(&digest[12..]))
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct KickStream {
    pub id: String,
    pub slug: String,
    pub title: String,
    pub category: String,
    pub url: String,
    pub started_at: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct InstagramMedia {
    pub id: String,
    pub caption: String,
    pub media_type: String,
    pub url: String,
    pub timestamp: String,
    pub permalink: String,
}

#[derive(Debug, Deserialize)]
struct InstagramMediaResponse {
    #[serde(default)]
    data: Vec<InstagramMediaPayload>,
    #[serde(default)]
    error: Option<InstagramApiError>,
}

#[derive(Debug, Deserialize)]
struct InstagramApiError {
    #[serde(default)]
    message: String,
    #[serde(default)]
    code: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct InstagramMediaPayload {
    id: String,
    #[serde(default)]
    caption: String,
    #[serde(default)]
    media_type: String,
    #[serde(default)]
    media_url: String,
    #[serde(default)]
    permalink: String,
    #[serde(default)]
    timestamp: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct TikTokVideo {
    pub id: String,
    pub title: String,
    pub description: String,
    pub created_at: String,
    pub url: String,
    pub embed_url: Option<String>,
}

#[derive(Clone)]
pub struct TokenCipher {
    key: Arc<[u8; 32]>,
}

impl TokenCipher {
    pub fn new(secret: &str) -> anyhow::Result<Self> {
        if secret.trim().len() < 24 {
            anyhow::bail!("token_cipher_secret_too_short");
        }
        let digest = Sha256::digest(format!("vozen-helper:tiktok:v1:{secret}").as_bytes());
        let mut key = [0_u8; 32];
        key.copy_from_slice(&digest);
        Ok(Self { key: Arc::new(key) })
    }

    pub fn seal(&self, plaintext: &str) -> anyhow::Result<String> {
        let mut nonce_bytes = [0_u8; 12];
        SystemRandom::new()
            .fill(&mut nonce_bytes)
            .map_err(|_| anyhow::anyhow!("token_cipher_random_failed"))?;
        let key = LessSafeKey::new(
            UnboundKey::new(&aead::AES_256_GCM, self.key.as_ref())
                .map_err(|_| anyhow::anyhow!("token_cipher_key_failed"))?,
        );
        let mut payload = plaintext.as_bytes().to_vec();
        key.seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce_bytes),
            Aad::from(b"vozen-helper:tiktok:v1"),
            &mut payload,
        )
        .map_err(|_| anyhow::anyhow!("token_cipher_seal_failed"))?;
        let mut encoded = nonce_bytes.to_vec();
        encoded.extend_from_slice(&payload);
        Ok(URL_SAFE_NO_PAD.encode(encoded))
    }

    pub fn open(&self, sealed: &str) -> anyhow::Result<String> {
        let decoded = URL_SAFE_NO_PAD
            .decode(sealed)
            .map_err(|_| anyhow::anyhow!("token_cipher_invalid_encoding"))?;
        if decoded.len() <= 12 + aead::AES_256_GCM.tag_len() {
            anyhow::bail!("token_cipher_invalid_payload");
        }
        let (nonce, ciphertext) = decoded.split_at(12);
        let mut nonce_bytes = [0_u8; 12];
        nonce_bytes.copy_from_slice(nonce);
        let key = LessSafeKey::new(
            UnboundKey::new(&aead::AES_256_GCM, self.key.as_ref())
                .map_err(|_| anyhow::anyhow!("token_cipher_key_failed"))?,
        );
        let mut payload = ciphertext.to_vec();
        let plaintext = key
            .open_in_place(
                Nonce::assume_unique_for_key(nonce_bytes),
                Aad::from(b"vozen-helper:tiktok:v1"),
                &mut payload,
            )
            .map_err(|_| anyhow::anyhow!("token_cipher_open_failed"))?;
        String::from_utf8(plaintext.to_vec()).map_err(Into::into)
    }
}

#[derive(Clone)]
pub struct TikTokOAuthClient {
    client_key: Arc<str>,
    client_secret: Arc<str>,
    redirect_uri: Arc<str>,
    authorize_url: Arc<str>,
    token_url: Arc<str>,
    http: Client,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TikTokTokenGrant {
    pub access_token: String,
    pub expires_in: i64,
    pub open_id: String,
    pub refresh_expires_in: i64,
    pub refresh_token: String,
    pub scope: String,
    pub token_type: String,
}

impl TikTokOAuthClient {
    pub fn from_env() -> Option<Self> {
        Self::new(
            std::env::var("TIKTOK_CLIENT_KEY").ok()?,
            std::env::var("TIKTOK_CLIENT_SECRET").ok()?,
            std::env::var("TIKTOK_REDIRECT_URI").ok()?,
            "https://www.tiktok.com/v2/auth/authorize/",
            "https://open.tiktokapis.com/v2/oauth/token/",
        )
    }

    pub fn new(
        client_key: impl Into<String>,
        client_secret: impl Into<String>,
        redirect_uri: impl Into<String>,
        authorize_url: impl Into<String>,
        token_url: impl Into<String>,
    ) -> Option<Self> {
        let client_key = client_key.into().trim().to_owned();
        let client_secret = client_secret.into().trim().to_owned();
        let redirect_uri = redirect_uri.into().trim().to_owned();
        let authorize_url = authorize_url.into().trim().to_owned();
        let token_url = token_url.into().trim().to_owned();
        let valid_url =
            |value: &str| value.starts_with("https://") || value.starts_with("http://localhost");
        if client_key.is_empty()
            || client_secret.len() < 8
            || !valid_url(&redirect_uri)
            || !valid_url(&authorize_url)
            || !valid_url(&token_url)
        {
            return None;
        }
        Some(Self {
            client_key: Arc::from(client_key),
            client_secret: Arc::from(client_secret),
            redirect_uri: Arc::from(redirect_uri),
            authorize_url: Arc::from(authorize_url),
            token_url: Arc::from(token_url),
            http: Client::builder()
                .timeout(Duration::from_secs(15))
                .user_agent("Vozen-Helper/1.0 (+https://vozen.org)")
                .build()
                .ok()?,
        })
    }

    pub fn authorization_url(&self, state: &str) -> anyhow::Result<String> {
        if state.trim().is_empty() || state.len() > 1_024 {
            anyhow::bail!("tiktok_oauth_invalid_state");
        }
        let mut url = Url::parse(&self.authorize_url)?;
        url.query_pairs_mut()
            .append_pair("client_key", &self.client_key)
            .append_pair("scope", "user.info.basic,video.list")
            .append_pair("response_type", "code")
            .append_pair("redirect_uri", &self.redirect_uri)
            .append_pair("state", state);
        Ok(url.into())
    }

    pub async fn exchange_code(&self, code: &str) -> anyhow::Result<TikTokTokenGrant> {
        self.token_request(&[
            ("client_key", self.client_key.as_ref()),
            ("client_secret", self.client_secret.as_ref()),
            ("code", code),
            ("grant_type", "authorization_code"),
            ("redirect_uri", self.redirect_uri.as_ref()),
        ])
        .await
    }

    pub async fn refresh(&self, refresh_token: &str) -> anyhow::Result<TikTokTokenGrant> {
        self.token_request(&[
            ("client_key", self.client_key.as_ref()),
            ("client_secret", self.client_secret.as_ref()),
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
        ])
        .await
    }

    async fn token_request(&self, form: &[(&str, &str)]) -> anyhow::Result<TikTokTokenGrant> {
        let response = self
            .http
            .post(self.token_url.as_ref())
            .form(form)
            .send()
            .await?;
        if !response.status().is_success() {
            anyhow::bail!("tiktok_oauth_error:{}", response.status());
        }
        let grant: TikTokTokenGrant = bounded_provider_json(response).await?;
        if grant.access_token.is_empty()
            || grant.refresh_token.is_empty()
            || grant.open_id.is_empty()
        {
            anyhow::bail!("tiktok_oauth_invalid_grant");
        }
        Ok(grant)
    }
}

#[derive(Debug, Deserialize)]
struct TikTokVideoResponse {
    #[serde(default)]
    data: TikTokVideoData,
    #[serde(default)]
    error: TikTokApiError,
}

#[derive(Debug, Default, Deserialize)]
struct TikTokVideoData {
    #[serde(default)]
    videos: Vec<TikTokVideoPayload>,
}

#[derive(Debug, Default, Deserialize)]
struct TikTokApiError {
    #[serde(default)]
    code: String,
    #[serde(default)]
    message: String,
}

#[derive(Debug, Deserialize)]
struct TikTokVideoPayload {
    id: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    video_description: String,
    #[serde(default)]
    create_time: i64,
    #[serde(default)]
    share_url: String,
    #[serde(default)]
    embed_link: Option<String>,
}

impl TikTokClient {
    pub fn from_env() -> Option<Self> {
        Self::new(
            std::env::var("TIKTOK_ACCESS_TOKEN").ok()?,
            std::env::var("TIKTOK_API_BASE_URL")
                .unwrap_or_else(|_| "https://open.tiktokapis.com".into()),
        )
    }

    pub fn new(access_token: impl Into<String>, base_url: impl Into<String>) -> Option<Self> {
        let access_token = access_token.into().trim().to_owned();
        let base_url = base_url.into().trim().trim_end_matches('/').to_owned();
        if access_token.is_empty()
            || access_token.len() > 2_000
            || !(base_url.starts_with("https://") || base_url.starts_with("http://localhost"))
        {
            return None;
        }
        Some(Self {
            access_token: Arc::from(access_token),
            base_url: Arc::from(base_url),
            http: Client::builder()
                .timeout(Duration::from_secs(10))
                .user_agent("Vozen-Helper/1.0 (+https://vozen.org)")
                .build()
                .expect("valid TikTok HTTP client"),
        })
    }

    pub fn is_configured(&self) -> bool {
        !self.access_token.is_empty()
    }

    pub async fn latest_videos(&self) -> anyhow::Result<Vec<TikTokVideo>> {
        let response = self
            .http
            .post(format!(
                "{}/v2/video/list/?fields=id,title,video_description,create_time,share_url,embed_link",
                self.base_url
            ))
            .bearer_auth(self.access_token.as_ref())
            .json(&serde_json::json!({ "max_count": 20 }))
            .send()
            .await?;
        if !response.status().is_success() {
            anyhow::bail!("tiktok_api_error:{}", response.status());
        }
        let payload: TikTokVideoResponse = bounded_provider_json(response).await?;
        if !payload.error.code.is_empty() && payload.error.code != "ok" {
            anyhow::bail!(
                "tiktok_api_error:{}:{}",
                payload.error.code,
                payload.error.message
            );
        }
        Ok(payload
            .data
            .videos
            .into_iter()
            .filter(|video| !video.id.trim().is_empty())
            .take(20)
            .map(|video| TikTokVideo {
                id: video.id,
                title: video.title,
                description: video.video_description,
                created_at: video.create_time.to_string(),
                url: video.share_url,
                embed_url: video.embed_link,
            })
            .collect())
    }
}

impl Default for TikTokClient {
    fn default() -> Self {
        Self::new("missing-access-token", "https://open.tiktokapis.com").expect("valid default")
    }
}

impl InstagramClient {
    pub fn from_env() -> Option<Self> {
        Self::new(
            std::env::var("META_INSTAGRAM_ACCESS_TOKEN").ok()?,
            std::env::var("META_INSTAGRAM_USER_ID").ok()?,
            std::env::var("META_GRAPH_API_BASE_URL")
                .unwrap_or_else(|_| "https://graph.facebook.com/v22.0".into()),
        )
    }

    pub fn new(
        access_token: impl Into<String>,
        user_id: impl Into<String>,
        base_url: impl Into<String>,
    ) -> Option<Self> {
        let access_token = access_token.into().trim().to_owned();
        let user_id = user_id.into().trim().to_owned();
        let base_url = base_url.into().trim().trim_end_matches('/').to_owned();
        if access_token.is_empty()
            || access_token.len() > 8_000
            || user_id.is_empty()
            || user_id.len() > 64
            || !user_id.chars().all(|character| character.is_ascii_digit())
            || !(base_url.starts_with("https://") || base_url.starts_with("http://localhost"))
        {
            return None;
        }
        Some(Self {
            access_token: Arc::from(access_token),
            user_id: Arc::from(user_id),
            base_url: Arc::from(base_url),
            http: Client::builder()
                .timeout(Duration::from_secs(10))
                .user_agent("Vozen-Helper/1.0 (+https://vozen.org)")
                .build()
                .expect("valid Meta HTTP client"),
        })
    }

    pub fn is_configured(&self) -> bool {
        !self.access_token.is_empty() && !self.user_id.is_empty()
    }

    pub async fn latest_media(&self) -> anyhow::Result<Vec<InstagramMedia>> {
        let response = self
            .http
            .get(format!("{}/{}/media", self.base_url, self.user_id))
            .bearer_auth(self.access_token.as_ref())
            .query(&[
                (
                    "fields",
                    "id,caption,media_type,media_url,permalink,timestamp",
                ),
                ("limit", "25"),
            ])
            .send()
            .await?;
        if !response.status().is_success() {
            anyhow::bail!("instagram_api_error:{}", response.status());
        }
        let payload: InstagramMediaResponse = bounded_provider_json(response).await?;
        if let Some(error) = payload.error {
            anyhow::bail!(
                "instagram_api_error:{}:{}",
                error
                    .code
                    .map(|code| code.to_string())
                    .unwrap_or_else(|| "unknown".into()),
                error.message
            );
        }
        Ok(payload
            .data
            .into_iter()
            .filter(|media| !media.id.trim().is_empty() && !media.permalink.trim().is_empty())
            .take(25)
            .map(|media| InstagramMedia {
                id: media.id,
                caption: media.caption.chars().take(2_000).collect(),
                media_type: media.media_type.chars().take(40).collect(),
                url: media.media_url.chars().take(2_000).collect(),
                timestamp: media.timestamp.chars().take(80).collect(),
                permalink: media.permalink.chars().take(2_000).collect(),
            })
            .collect())
    }
}

impl Default for InstagramClient {
    fn default() -> Self {
        Self::new(
            "missing-access-token",
            "0",
            "https://graph.facebook.com/v22.0",
        )
        .expect("valid default")
    }
}

impl KickClient {
    pub fn from_env() -> Option<Self> {
        Self::new(
            std::env::var("KICK_ACCESS_TOKEN").ok()?,
            std::env::var("KICK_API_BASE_URL")
                .unwrap_or_else(|_| "https://api.kick.com/public/v1".into()),
        )
    }

    pub fn new(access_token: impl Into<String>, base_url: impl Into<String>) -> Option<Self> {
        let access_token = access_token.into().trim().to_owned();
        let base_url = base_url.into().trim().trim_end_matches('/').to_owned();
        if access_token.is_empty()
            || access_token.len() > 8_000
            || !(base_url.starts_with("https://") || base_url.starts_with("http://localhost"))
        {
            return None;
        }
        Some(Self {
            access_token: Arc::from(access_token),
            base_url: Arc::from(base_url),
            http: Client::builder()
                .timeout(Duration::from_secs(10))
                .user_agent("Vozen-Helper/1.0 (+https://vozen.org)")
                .build()
                .expect("valid Kick HTTP client"),
        })
    }

    pub fn is_configured(&self) -> bool {
        !self.access_token.is_empty()
    }

    /// Returns the current live stream for a channel slug, if any.
    pub async fn latest_stream(&self, slug: &str) -> anyhow::Result<Option<KickStream>> {
        let response = self
            .http
            .get(format!("{}/channels", self.base_url))
            .bearer_auth(self.access_token.as_ref())
            .query(&[("slug", slug)])
            .send()
            .await?;
        if !response.status().is_success() {
            anyhow::bail!("kick_api_error:{}", response.status());
        }
        let payload: serde_json::Value = bounded_provider_json(response).await?;
        if let Some(error) = payload.get("message").and_then(serde_json::Value::as_str)
            && payload.get("data").is_none()
        {
            anyhow::bail!("kick_api_error:{error}");
        }
        let data = payload
            .get("data")
            .and_then(serde_json::Value::as_array)
            .cloned()
            .unwrap_or_default();
        let channel = data.into_iter().next().unwrap_or(serde_json::Value::Null);
        let Some(stream) = channel.get("stream").filter(|value| !value.is_null()) else {
            return Ok(None);
        };
        let is_live = stream
            .get("is_live")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(true);
        if !is_live {
            return Ok(None);
        }
        let id = stream
            .get("id")
            .or_else(|| stream.get("stream_id"))
            .map(|value| value.to_string().trim_matches('"').to_string())
            .filter(|value| !value.is_empty() && value.len() <= 128)
            .unwrap_or_else(|| format!("{}-live", slug));
        let title = stream
            .get("stream_title")
            .or_else(|| stream.get("title"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .chars()
            .take(300)
            .collect::<String>();
        let category = stream
            .get("category")
            .and_then(|value| value.get("name").or(Some(value)))
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .chars()
            .take(160)
            .collect::<String>();
        let resolved_slug = channel
            .get("slug")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(slug)
            .chars()
            .take(80)
            .collect::<String>();
        let started_at = stream
            .get("start_time")
            .or_else(|| stream.get("started_at"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .chars()
            .take(80)
            .collect::<String>();
        Ok(Some(KickStream {
            id,
            slug: resolved_slug.clone(),
            title,
            category,
            url: format!("https://kick.com/{resolved_slug}"),
            started_at,
        }))
    }
}

impl Default for KickClient {
    fn default() -> Self {
        Self::new("missing-access-token", "https://api.kick.com/public/v1").expect("valid default")
    }
}

impl StripeConnectClient {
    pub fn from_env() -> Option<Self> {
        Self::new(
            std::env::var("STRIPE_SECRET_KEY").ok()?,
            std::env::var("STRIPE_WEBHOOK_SECRET").ok()?,
        )
    }

    pub fn new(secret_key: impl Into<String>, webhook_secret: impl Into<String>) -> Option<Self> {
        let secret_key = secret_key.into().trim().to_owned();
        let webhook_secret = webhook_secret.into().trim().to_owned();
        if secret_key.len() < 16
            || secret_key.len() > 8_000
            || webhook_secret.len() < 16
            || webhook_secret.len() > 8_000
            || !(secret_key.starts_with("sk_") || secret_key.starts_with("rk_"))
            || !webhook_secret.starts_with("whsec_")
        {
            return None;
        }
        Some(Self {
            secret_key: Arc::from(secret_key),
            webhook_secret: Arc::from(webhook_secret),
        })
    }

    pub fn is_configured(&self) -> bool {
        !self.secret_key.is_empty()
    }

    pub fn verify_webhook(&self, payload: &[u8], signature: &str, now: i64) -> bool {
        let mut timestamp = None;
        let mut signatures = Vec::new();
        for item in signature.split(',') {
            if let Some(value) = item.strip_prefix("t=") {
                timestamp = value.parse::<i64>().ok();
            }
            if let Some(value) = item.strip_prefix("v1=") {
                signatures.push(value.to_owned());
            }
        }
        let Some(timestamp) = timestamp else {
            return false;
        };
        if now.abs_diff(timestamp) > 300 || signatures.is_empty() {
            return false;
        }
        let mut mac = Hmac::<Sha256>::new_from_slice(self.webhook_secret.as_bytes())
            .expect("valid stripe hmac key");
        mac.update(timestamp.to_string().as_bytes());
        mac.update(b".");
        mac.update(payload);
        let expected = hex::encode(mac.finalize().into_bytes());
        signatures.into_iter().any(|candidate| {
            subtle::ConstantTimeEq::ct_eq(candidate.as_bytes(), expected.as_bytes()).into()
        })
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct BlueskyPost {
    pub uri: String,
    pub handle: String,
    pub text: String,
    pub created_at: String,
    pub url: String,
}

#[derive(Debug, Deserialize)]
struct BlueskyAuthorFeedResponse {
    #[serde(default)]
    feed: Vec<BlueskyFeedItem>,
}

#[derive(Debug, Deserialize)]
struct BlueskyFeedItem {
    post: BlueskyPostPayload,
}

#[derive(Debug, Deserialize)]
struct BlueskyPostPayload {
    uri: String,
    author: BlueskyAuthor,
    record: BlueskyRecord,
}

#[derive(Debug, Deserialize)]
struct BlueskyAuthor {
    handle: String,
}

#[derive(Debug, Deserialize)]
struct BlueskyRecord {
    #[serde(default)]
    text: String,
    #[serde(rename = "createdAt", default)]
    created_at: String,
}

impl BlueskyClient {
    pub fn new() -> Self {
        Self {
            http: Client::builder()
                .timeout(Duration::from_secs(10))
                .user_agent("Vozen-Helper/1.0 (+https://vozen.org)")
                .build()
                .expect("valid Bluesky HTTP client"),
        }
    }

    pub async fn latest_post(&self, raw_handle: &str) -> anyhow::Result<Option<BlueskyPost>> {
        let handle = normalize_bluesky_handle(raw_handle)?;
        let response = self
            .http
            .get("https://public.api.bsky.app/xrpc/app.bsky.feed.getAuthorFeed")
            .query(&[("actor", handle.as_str()), ("limit", "10")])
            .send()
            .await?;
        if !response.status().is_success() {
            anyhow::bail!("bluesky_api_error:{}", response.status());
        }
        let payload: BlueskyAuthorFeedResponse = bounded_provider_json(response).await?;
        Ok(payload.feed.into_iter().next().map(|item| {
            let post = item.post;
            let rkey = post.uri.rsplit('/').next().unwrap_or_default();
            let url = format!(
                "https://bsky.app/profile/{}/post/{}",
                post.author.handle, rkey
            );
            BlueskyPost {
                uri: post.uri,
                handle: post.author.handle,
                text: post.record.text,
                created_at: post.record.created_at,
                url,
            }
        }))
    }
}

impl Default for BlueskyClient {
    fn default() -> Self {
        Self::new()
    }
}

pub fn normalize_bluesky_handle(raw_handle: &str) -> anyhow::Result<String> {
    let handle = raw_handle
        .trim()
        .trim_start_matches('@')
        .to_ascii_lowercase();
    if !(3..=253).contains(&handle.len())
        || handle.starts_with('.')
        || handle.ends_with('.')
        || handle.contains("..")
        || !handle
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        anyhow::bail!("invalid_bluesky_handle");
    }
    Ok(handle)
}

/// Read-only CoinGecko client used by the crypto query and statistics
/// features. The public API is used by default; an optional
/// COINGECKO_API_KEY is sent as a demo key when the operator has one, but it
/// is never exposed to the panel or stored in guild configuration.
#[derive(Clone)]
pub struct CoinGeckoClient {
    api_key: Option<Arc<str>>,
    http: Client,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CoinGeckoQuote {
    pub id: String,
    pub currency: String,
    pub price: f64,
    pub change_24h: Option<f64>,
    pub last_updated_at: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct CoinGeckoPrice {
    #[serde(flatten)]
    values: HashMap<String, serde_json::Value>,
}

impl CoinGeckoClient {
    pub fn new() -> Self {
        let api_key = std::env::var("COINGECKO_API_KEY")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .map(Arc::<str>::from);
        Self {
            api_key,
            http: Client::builder()
                .timeout(Duration::from_secs(10))
                .user_agent("Vozen-Helper/1.0 (+https://vozen.org)")
                .build()
                .expect("valid CoinGecko HTTP client"),
        }
    }

    pub fn has_api_key(&self) -> bool {
        self.api_key.is_some()
    }

    pub async fn quotes(
        &self,
        ids: &[String],
        currency: &str,
    ) -> anyhow::Result<Vec<CoinGeckoQuote>> {
        if ids.is_empty() || ids.len() > 20 {
            anyhow::bail!("invalid_coingecko_ids");
        }
        let normalized_ids = ids
            .iter()
            .map(|id| normalize_coingecko_id(id))
            .collect::<anyhow::Result<Vec<_>>>()?;
        let currency = normalize_currency(currency)?;
        let mut request = self
            .http
            .get("https://api.coingecko.com/api/v3/simple/price")
            .query(&[
                ("ids", normalized_ids.join(",")),
                ("vs_currencies", currency.clone()),
                ("include_24hr_change", "true".to_string()),
                ("include_last_updated_at", "true".to_string()),
            ]);
        if let Some(api_key) = &self.api_key {
            request = request.header("x-cg-demo-api-key", api_key.as_ref());
        }
        let response = request.send().await?.error_for_status()?;
        let payload: HashMap<String, CoinGeckoPrice> = bounded_provider_json(response).await?;
        Ok(normalized_ids
            .into_iter()
            .filter_map(|id| {
                let entry = payload.get(&id)?;
                let price = entry.values.get(&currency)?.as_f64()?;
                let change_24h = entry
                    .values
                    .get(&format!("{currency}_24h_change"))
                    .and_then(serde_json::Value::as_f64);
                let last_updated_at = entry
                    .values
                    .get("last_updated_at")
                    .and_then(serde_json::Value::as_i64);
                Some(CoinGeckoQuote {
                    id,
                    currency: currency.clone(),
                    price,
                    change_24h,
                    last_updated_at,
                })
            })
            .collect())
    }
}

impl Default for CoinGeckoClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Read-only JSON-RPC client for gas estimates. Endpoints are deliberately
/// supplied by the operator through the environment; the Helper never
/// accepts arbitrary RPC URLs from guild configuration.
#[derive(Clone)]
pub struct GasClient {
    endpoints: Arc<HashMap<String, Arc<str>>>,
    http: Client,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct GasQuote {
    pub network: String,
    pub gas_price_gwei: f64,
    pub block_number: Option<u64>,
}

impl GasClient {
    pub fn new() -> Self {
        let mut endpoints = HashMap::new();
        for (network, variable) in [
            ("ethereum", "ETHEREUM_RPC_URL"),
            ("polygon", "POLYGON_RPC_URL"),
            ("arbitrum", "ARBITRUM_RPC_URL"),
            ("base", "BASE_RPC_URL"),
        ] {
            let Some(value) = std::env::var(variable)
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
            else {
                continue;
            };
            if validate_rpc_url(&value).is_ok() {
                endpoints.insert(network.to_string(), Arc::<str>::from(value));
            }
        }
        Self {
            endpoints: Arc::new(endpoints),
            http: Client::builder()
                .timeout(Duration::from_secs(8))
                .user_agent("Vozen-Helper/1.0 (+https://vozen.org)")
                .build()
                .expect("valid gas HTTP client"),
        }
    }

    pub fn configured_networks(&self) -> Vec<String> {
        let mut networks = self.endpoints.keys().cloned().collect::<Vec<_>>();
        networks.sort();
        networks
    }

    pub async fn quote(&self, raw_network: &str) -> anyhow::Result<GasQuote> {
        let network = normalize_network(raw_network)?;
        let endpoint = self
            .endpoints
            .get(&network)
            .ok_or_else(|| anyhow::anyhow!("rpc_network_not_configured"))?;
        let request = |method: &str| {
            self.http.post(endpoint.as_ref()).json(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": method,
                "params": []
            }))
        };
        let gas_response = request("eth_gasPrice").send().await?.error_for_status()?;
        let gas_payload: serde_json::Value = bounded_provider_json(gas_response).await?;
        let gas_hex = gas_payload
            .get("result")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("rpc_missing_gas_price"))?;
        let gas_wei = u128::from_str_radix(gas_hex.trim_start_matches("0x"), 16)
            .map_err(|_| anyhow::anyhow!("rpc_invalid_gas_price"))?;
        let block_number = match request("eth_blockNumber").send().await {
            Ok(response) => bounded_provider_json::<serde_json::Value>(response)
                .await
                .ok()
                .and_then(|value| {
                    value
                        .get("result")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned)
                })
                .and_then(|value| u64::from_str_radix(value.trim_start_matches("0x"), 16).ok()),
            Err(_) => None,
        };
        Ok(GasQuote {
            network,
            gas_price_gwei: gas_wei as f64 / 1_000_000_000.0,
            block_number,
        })
    }
}

impl Default for GasClient {
    fn default() -> Self {
        Self::new()
    }
}

pub fn normalize_network(raw_network: &str) -> anyhow::Result<String> {
    let network = raw_network.trim().to_ascii_lowercase();
    if !matches!(
        network.as_str(),
        "ethereum" | "polygon" | "arbitrum" | "base"
    ) {
        anyhow::bail!("unsupported_rpc_network");
    }
    Ok(network)
}

fn validate_rpc_url(raw_url: &str) -> anyhow::Result<()> {
    let url = Url::parse(raw_url).map_err(|_| anyhow::anyhow!("invalid_rpc_url"))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || url.username() != ""
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        anyhow::bail!("invalid_rpc_url");
    }
    Ok(())
}

pub fn normalize_coingecko_id(raw_id: &str) -> anyhow::Result<String> {
    let id = raw_id.trim().to_ascii_lowercase();
    if !(1..=64).contains(&id.len())
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        || id.starts_with('-')
        || id.ends_with('-')
    {
        anyhow::bail!("invalid_coingecko_id");
    }
    Ok(id)
}

fn normalize_currency(raw_currency: &str) -> anyhow::Result<String> {
    let currency = raw_currency.trim().to_ascii_lowercase();
    if !(3..=10).contains(&currency.len())
        || !currency.bytes().all(|byte| byte.is_ascii_lowercase())
    {
        anyhow::bail!("invalid_currency");
    }
    Ok(currency)
}

/// Official Twitch Helix/EventSub client. Credentials and the EventSub
/// signing secret are always read from the server environment.
#[derive(Clone)]
pub struct TwitchClient {
    client_id: Arc<str>,
    client_secret: Arc<str>,
    callback_url: Arc<str>,
    eventsub_secret: Arc<str>,
    http: Client,
    token: Arc<AsyncMutex<Option<TwitchToken>>>,
}

#[derive(Clone)]
struct TwitchToken {
    access_token: String,
    expires_at: Instant,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct TwitchUser {
    pub id: String,
    pub login: String,
    pub display_name: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct TwitchChannelSearchResult {
    pub broadcaster_login: String,
    pub display_name: String,
    pub game_name: String,
    pub title: String,
    pub is_live: bool,
    pub url: String,
}

#[derive(Debug, Deserialize)]
struct TwitchTokenResponse {
    access_token: String,
    expires_in: u64,
}

#[derive(Debug, Deserialize)]
struct TwitchUsersResponse {
    #[serde(default)]
    data: Vec<TwitchUserPayload>,
}

#[derive(Debug, Deserialize)]
struct TwitchSearchChannelsResponse {
    #[serde(default)]
    data: Vec<TwitchSearchChannelPayload>,
}

#[derive(Debug, Deserialize)]
struct TwitchSearchChannelPayload {
    broadcaster_login: String,
    display_name: String,
    #[serde(default)]
    game_name: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    is_live: bool,
}

#[derive(Debug, Deserialize)]
struct TwitchUserPayload {
    id: String,
    login: String,
    display_name: String,
}

#[derive(Debug, Deserialize)]
struct TwitchEventSubResponse {
    #[serde(default)]
    data: Vec<TwitchEventSubPayload>,
}

#[derive(Debug, Deserialize)]
struct TwitchEventSubPayload {
    status: String,
    #[serde(default)]
    condition: HashMap<String, String>,
}

impl TwitchClient {
    pub fn from_env() -> Option<Self> {
        let callback_url = std::env::var("TWITCH_EVENTSUB_CALLBACK_URL")
            .ok()
            .or_else(|| {
                std::env::var("TWITCH_CALLBACK_URL")
                    .ok()
                    .filter(|value| value.contains("/eventsub"))
            })
            .unwrap_or_else(|| "https://api.vozen.org/rust/api/providers/twitch/eventsub".into());
        Self::new(
            std::env::var("TWITCH_CLIENT_ID").ok()?,
            std::env::var("TWITCH_CLIENT_SECRET").ok()?,
            callback_url,
            std::env::var("TWITCH_EVENTSUB_SECRET").ok()?,
        )
    }

    pub fn new(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        callback_url: impl Into<String>,
        eventsub_secret: impl Into<String>,
    ) -> Option<Self> {
        let client_id = client_id.into().trim().to_string();
        let client_secret = client_secret.into().trim().to_string();
        let callback_url = callback_url.into().trim().to_string();
        let eventsub_secret = eventsub_secret.into().trim().to_string();
        if client_id.is_empty()
            || client_secret.is_empty()
            || !(10..=100).contains(&eventsub_secret.len())
            || !callback_url.starts_with("https://")
        {
            return None;
        }
        Some(Self {
            client_id: Arc::from(client_id),
            client_secret: Arc::from(client_secret),
            callback_url: Arc::from(callback_url),
            eventsub_secret: Arc::from(eventsub_secret),
            http: Client::builder()
                .timeout(Duration::from_secs(10))
                .user_agent("Vozen-Helper/1.0 (+https://vozen.org)")
                .build()
                .expect("valid Twitch HTTP client"),
            token: Arc::new(AsyncMutex::new(None)),
        })
    }

    pub fn is_configured(&self) -> bool {
        !self.client_id.is_empty() && !self.client_secret.is_empty()
    }

    pub fn callback_url(&self) -> &str {
        &self.callback_url
    }

    pub fn eventsub_secret(&self) -> &str {
        &self.eventsub_secret
    }

    pub async fn user(&self, login: &str) -> anyhow::Result<Option<TwitchUser>> {
        let login = login.trim().trim_start_matches('@').to_ascii_lowercase();
        if login.is_empty()
            || login.len() > 25
            || !login
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            anyhow::bail!("invalid_twitch_login");
        }
        let token = self.app_token().await?;
        let response = self
            .http
            .get("https://api.twitch.tv/helix/users")
            .query(&[("login", login.as_str())])
            .header("Client-Id", self.client_id.as_ref())
            .bearer_auth(token)
            .send()
            .await?;
        let status = response.status();
        if !status.is_success() {
            anyhow::bail!("twitch_api_error:{status}");
        }
        let payload: TwitchUsersResponse = bounded_provider_json(response).await?;
        Ok(payload.data.into_iter().next().map(|value| TwitchUser {
            id: value.id,
            login: value.login,
            display_name: value.display_name,
        }))
    }

    /// Search public channels through Twitch Helix. This uses the existing
    /// app access token and never scrapes twitch.tv pages.
    pub async fn search_channels(
        &self,
        query: &str,
        max_results: usize,
    ) -> anyhow::Result<Vec<TwitchChannelSearchResult>> {
        let query = query.trim();
        if !(1..=128).contains(&query.len()) {
            anyhow::bail!("invalid_twitch_search_query");
        }
        let first = max_results.clamp(1, 5).to_string();
        let token = self.app_token().await?;
        let response = self
            .http
            .get("https://api.twitch.tv/helix/search/channels")
            .query(&[("query", query), ("first", first.as_str())])
            .header("Client-Id", self.client_id.as_ref())
            .bearer_auth(token)
            .send()
            .await?;
        let status = response.status();
        if !status.is_success() {
            anyhow::bail!("twitch_api_error:{status}");
        }
        let payload: TwitchSearchChannelsResponse = bounded_provider_json(response).await?;
        Ok(payload
            .data
            .into_iter()
            .map(|item| TwitchChannelSearchResult {
                url: format!("https://twitch.tv/{}", item.broadcaster_login),
                broadcaster_login: item.broadcaster_login,
                display_name: item.display_name,
                game_name: item.game_name,
                title: item.title,
                is_live: item.is_live,
            })
            .collect())
    }

    /// Ensures a single stream.online EventSub subscription exists for the
    /// broadcaster. Twitch may resend notifications, so the webhook handler
    /// deduplicates by EventSub message id before dispatching to Discord.
    pub async fn ensure_stream_online_subscription(&self, user_id: &str) -> anyhow::Result<()> {
        let token = self.app_token().await?;
        let existing = self
            .http
            .get("https://api.twitch.tv/helix/eventsub/subscriptions")
            .query(&[("type", "stream.online"), ("user_id", user_id)])
            .header("Client-Id", self.client_id.as_ref())
            .bearer_auth(&token)
            .send()
            .await?;
        if !existing.status().is_success() {
            anyhow::bail!("twitch_api_error:{}", existing.status());
        }
        let payload: TwitchEventSubResponse = existing.json().await?;
        if payload.data.iter().any(|item| {
            item.status == "enabled"
                && item
                    .condition
                    .get("broadcaster_user_id")
                    .is_some_and(|value| value == user_id)
        }) {
            return Ok(());
        }
        let response = self
            .http
            .post("https://api.twitch.tv/helix/eventsub/subscriptions")
            .header("Client-Id", self.client_id.as_ref())
            .bearer_auth(token)
            .json(&serde_json::json!({
                "type": "stream.online",
                "version": "1",
                "condition": { "broadcaster_user_id": user_id },
                "transport": {
                    "method": "webhook",
                    "callback": self.callback_url.as_ref(),
                    "secret": self.eventsub_secret.as_ref()
                }
            }))
            .send()
            .await?;
        if response.status().is_success() {
            return Ok(());
        }
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        if status == reqwest::StatusCode::CONFLICT || body.contains("already exists") {
            return Ok(());
        }
        anyhow::bail!("twitch_api_error:{status}");
    }

    /// Read-only check used by health endpoints. Unlike
    /// `ensure_stream_online_subscription`, this never creates or changes a
    /// Twitch subscription.
    pub async fn has_stream_online_subscription(&self, user_id: &str) -> anyhow::Result<bool> {
        let token = self.app_token().await?;
        let response = self
            .http
            .get("https://api.twitch.tv/helix/eventsub/subscriptions")
            .query(&[("type", "stream.online"), ("user_id", user_id)])
            .header("Client-Id", self.client_id.as_ref())
            .bearer_auth(token)
            .send()
            .await?;
        if !response.status().is_success() {
            anyhow::bail!("twitch_api_error:{}", response.status());
        }
        let payload: TwitchEventSubResponse = bounded_provider_json(response).await?;
        Ok(payload.data.iter().any(|item| {
            item.status == "enabled"
                && item
                    .condition
                    .get("broadcaster_user_id")
                    .is_some_and(|value| value == user_id)
        }))
    }

    async fn app_token(&self) -> anyhow::Result<String> {
        let mut cached = self.token.lock().await;
        if let Some(value) = cached.as_ref()
            && value.expires_at > Instant::now() + Duration::from_secs(60)
        {
            return Ok(value.access_token.clone());
        }
        let response = self
            .http
            .post("https://id.twitch.tv/oauth2/token")
            .form(&[
                ("client_id", self.client_id.as_ref()),
                ("client_secret", self.client_secret.as_ref()),
                ("grant_type", "client_credentials"),
            ])
            .send()
            .await?;
        if !response.status().is_success() {
            anyhow::bail!("twitch_auth_error:{}", response.status());
        }
        let value: TwitchTokenResponse = bounded_provider_json(response).await?;
        let token = TwitchToken {
            access_token: value.access_token.clone(),
            expires_at: Instant::now() + Duration::from_secs(value.expires_in),
        };
        *cached = Some(token);
        Ok(value.access_token)
    }
}

impl RssClient {
    pub fn new() -> Self {
        Self
    }

    pub async fn fetch(&self, raw_url: &str) -> anyhow::Result<Option<RssFeed>> {
        let (url, addresses) = validate_feed_url(raw_url).await?;
        let http = feed_http_client(&url, &addresses)?;
        let response = http.get(url.clone()).send().await?;
        let status = response.status();
        if !status.is_success() {
            anyhow::bail!("rss_http_error:{status}");
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_FEED_BYTES as u64)
        {
            anyhow::bail!("rss_feed_too_large");
        }
        let mut response = response;
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            if bytes.len().saturating_add(chunk.len()) > MAX_FEED_BYTES {
                anyhow::bail!("rss_feed_too_large");
            }
            bytes.extend_from_slice(&chunk);
        }
        let feed = parse_feed(&bytes)?;
        Ok(feed.map(|mut value| {
            value.url = url.to_string();
            value
        }))
    }
}

impl Default for RssClient {
    fn default() -> Self {
        Self::new()
    }
}

const MAX_FEED_BYTES: usize = 1_048_576;

const MAX_PROVIDER_JSON_BYTES: usize = 1_048_576;

async fn bounded_provider_json<T: serde::de::DeserializeOwned>(
    mut response: reqwest::Response,
) -> anyhow::Result<T> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_PROVIDER_JSON_BYTES as u64)
    {
        anyhow::bail!("provider_response_too_large");
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if bytes.len().saturating_add(chunk.len()) > MAX_PROVIDER_JSON_BYTES {
            anyhow::bail!("provider_response_too_large");
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(serde_json::from_slice(&bytes)?)
}

// Pin the validated DNS answers for this request, including HTTPS SNI/Host.
// Proxies must not resolve the hostname independently and bypass this check.
fn feed_http_client(url: &Url, addresses: &[SocketAddr]) -> anyhow::Result<Client> {
    Ok(Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .resolve_to_addrs(url.host_str().unwrap_or_default(), addresses)
        .user_agent("Vozen-Helper/1.0 (+https://vozen.org)")
        .build()?)
}

async fn validate_feed_url(raw_url: &str) -> anyhow::Result<(Url, Vec<SocketAddr>)> {
    if raw_url.chars().count() > 2_000 {
        anyhow::bail!("invalid_rss_url");
    }
    let url = Url::parse(raw_url.trim()).map_err(|_| anyhow::anyhow!("invalid_rss_url"))?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        anyhow::bail!("invalid_rss_url");
    }
    let host = url.host_str().unwrap_or_default().to_ascii_lowercase();
    if host == "localhost"
        || host.ends_with(".localhost")
        || host.ends_with(".local")
        || host.ends_with(".internal")
    {
        anyhow::bail!("rss_private_host");
    }
    let port = url
        .port_or_known_default()
        .ok_or_else(|| anyhow::anyhow!("invalid_rss_url"))?;
    let addresses = match url.host() {
        Some(url::Host::Ipv4(ip)) => vec![SocketAddr::new(ip.into(), port)],
        Some(url::Host::Ipv6(ip)) => vec![SocketAddr::new(ip.into(), port)],
        _ => tokio::time::timeout(
            Duration::from_secs(10),
            tokio::net::lookup_host((host.as_str(), port)),
        )
        .await
        .map_err(|_| anyhow::anyhow!("rss_host_unresolvable"))?
        .map_err(|_| anyhow::anyhow!("rss_host_unresolvable"))?
        .collect::<Vec<_>>(),
    };
    if addresses.is_empty()
        || addresses
            .iter()
            .any(|address| private_or_local(address.ip()))
    {
        anyhow::bail!("rss_private_host");
    }
    Ok((url, addresses))
}

fn private_or_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(value) => {
            let [a, b, _, _] = value.octets();
            value.is_private()
                || value.is_loopback()
                || value.is_link_local()
                || value.is_unspecified()
                || value.is_broadcast()
                || value.is_documentation()
                || a == 0
                || a >= 224
                || (a == 100 && (64..=127).contains(&b))
                || (a == 198 && (18..=19).contains(&b))
        }
        IpAddr::V6(value) => {
            if let Some(ip) = value.to_ipv4_mapped() {
                return private_or_local(IpAddr::V4(ip));
            }
            value.is_loopback()
                || value.is_unique_local()
                || value.is_unicast_link_local()
                || value.is_unspecified()
                || value.is_multicast()
                || value.segments()[0] & 0xe000 != 0x2000
                || (value.segments()[0] == 0x2001 && value.segments()[1] == 0x0db8)
        }
    }
}

#[derive(Default)]
struct RawRssItem {
    id: String,
    title: String,
    description: String,
    url: String,
    published_at: String,
}

fn parse_feed(bytes: &[u8]) -> anyhow::Result<Option<RssFeed>> {
    let mut reader = Reader::from_reader(bytes);
    // Keep whitespace around `Event::GeneralRef` entities (for example
    // `Hello &amp; welcome`), then trim each field once the item is complete.
    reader.config_mut().trim_text(false);
    let mut buffer = Vec::new();
    let mut feed_title = String::new();
    let mut current_tag = String::new();
    let mut current_item: Option<RawRssItem> = None;
    let mut first_item: Option<RawRssItem> = None;
    loop {
        match reader.read_event_into(&mut buffer) {
            Ok(Event::Start(event)) => {
                let name =
                    String::from_utf8_lossy(event.local_name().as_ref()).to_ascii_lowercase();
                if name == "item" || name == "entry" {
                    if first_item.is_none() {
                        current_item = Some(RawRssItem::default());
                    }
                    current_tag.clear();
                } else {
                    if let Some(item) = current_item.as_mut() {
                        if name == "link" {
                            for attribute in event.attributes().flatten() {
                                if attribute.key.as_ref() == b"href"
                                    && let Ok(value) = attribute.decoded_and_normalized_value(
                                        quick_xml::XmlVersion::Implicit1_0,
                                        reader.decoder(),
                                    )
                                {
                                    item.url = value.into_owned();
                                }
                            }
                        }
                        current_tag = name;
                    } else {
                        current_tag = name;
                    }
                }
            }
            Ok(Event::Empty(event)) => {
                if current_item.is_some()
                    && event.local_name().as_ref().eq_ignore_ascii_case(b"link")
                {
                    for attribute in event.attributes().flatten() {
                        if attribute.key.as_ref() == b"href"
                            && let Ok(value) = attribute.decoded_and_normalized_value(
                                quick_xml::XmlVersion::Implicit1_0,
                                reader.decoder(),
                            )
                            && let Some(item) = current_item.as_mut()
                        {
                            item.url = value.into_owned();
                        }
                    }
                }
            }
            Ok(Event::Text(event)) => assign_feed_text(
                &mut current_item,
                &mut feed_title,
                &current_tag,
                event.as_ref(),
            ),
            Ok(Event::CData(event)) => assign_feed_text(
                &mut current_item,
                &mut feed_title,
                &current_tag,
                event.as_ref(),
            ),
            Ok(Event::GeneralRef(event)) => {
                assign_feed_reference(&mut current_item, &mut feed_title, &current_tag, &event)
            }
            Ok(Event::End(event)) => {
                let name =
                    String::from_utf8_lossy(event.local_name().as_ref()).to_ascii_lowercase();
                if name == "item" || name == "entry" {
                    if let Some(mut item) = current_item.take() {
                        item.title = item.title.trim().to_string();
                        item.description = item.description.trim().to_string();
                        item.url = item.url.trim().to_string();
                        item.id = item.id.trim().to_string();
                        item.published_at = item.published_at.trim().to_string();
                        if item.id.is_empty() {
                            item.id = item.url.clone();
                        }
                        if item.id.is_empty() {
                            let mut digest = Sha256::new();
                            digest.update(format!(
                                "{}|{}|{}",
                                item.title, item.published_at, item.description
                            ));
                            item.id = hex::encode(digest.finalize());
                        }
                        if first_item.is_none() {
                            first_item = Some(item);
                        }
                    }
                    current_tag.clear();
                }
            }
            Ok(Event::Eof) => break,
            Err(error) => return Err(anyhow::anyhow!("rss_xml_error:{error}")),
            _ => {}
        }
        buffer.clear();
    }
    let Some(item) = first_item else {
        return Ok(None);
    };
    let item = RssItem {
        id: item.id,
        title: item.title,
        description: item.description,
        url: item.url,
        published_at: item.published_at,
        feed_title: feed_title.clone(),
    };
    Ok(Some(RssFeed {
        url: String::new(),
        title: feed_title,
        latest: Some(item),
    }))
}

fn assign_feed_text(
    current_item: &mut Option<RawRssItem>,
    feed_title: &mut String,
    current_tag: &str,
    bytes: &[u8],
) {
    let text = unescape(&String::from_utf8_lossy(bytes))
        .map(|value| value.into_owned())
        .unwrap_or_else(|_| String::from_utf8_lossy(bytes).into_owned());
    append_feed_text(current_item, feed_title, current_tag, &text);
}

fn assign_feed_reference(
    current_item: &mut Option<RawRssItem>,
    feed_title: &mut String,
    current_tag: &str,
    reference: &quick_xml::events::BytesRef<'_>,
) {
    let name = reference
        .decode()
        .map(|value| value.into_owned())
        .unwrap_or_default();
    let text = match name.as_str() {
        "amp" => "&".to_string(),
        "lt" => "<".to_string(),
        "gt" => ">".to_string(),
        "quot" => "\"".to_string(),
        "apos" => "'".to_string(),
        _ => reference
            .resolve_char_ref()
            .ok()
            .flatten()
            .map(|value| value.to_string())
            .unwrap_or_else(|| format!("&{name};")),
    };
    append_feed_text(current_item, feed_title, current_tag, &text);
}

fn append_feed_text(
    current_item: &mut Option<RawRssItem>,
    feed_title: &mut String,
    current_tag: &str,
    text: &str,
) {
    if let Some(item) = current_item.as_mut() {
        match current_tag {
            "title" => item.title.push_str(text),
            "description" | "summary" | "content" => item.description.push_str(text),
            "link" if item.url.is_empty() => item.url.push_str(text.trim()),
            "guid" | "id" => item.id.push_str(text),
            "pubdate" | "published" | "updated" | "date" => item.published_at.push_str(text),
            _ => {}
        }
    } else if current_tag == "title" && feed_title.is_empty() {
        *feed_title = text.to_string();
    }
}

#[derive(Debug, Deserialize)]
struct YouTubeChannelsResponse {
    #[serde(default)]
    items: Vec<YouTubeChannelItem>,
}

#[derive(Debug, Deserialize)]
struct YouTubeSearchResponse {
    #[serde(default)]
    items: Vec<YouTubeSearchItem>,
}

#[derive(Debug, Deserialize)]
struct YouTubeSearchItem {
    id: YouTubeSearchId,
    snippet: YouTubePlaylistSnippet,
}

#[derive(Debug, Default, Deserialize)]
struct YouTubeSearchId {
    #[serde(rename = "videoId", default)]
    video_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct YouTubeChannelItem {
    id: String,
    snippet: YouTubeChannelSnippet,
}

#[derive(Debug, Deserialize)]
struct YouTubeChannelDetailsResponse {
    #[serde(default)]
    items: Vec<YouTubeChannelDetailsItem>,
}

#[derive(Debug, Deserialize)]
struct YouTubeChannelDetailsItem {
    #[serde(rename = "contentDetails", default)]
    content_details: YouTubeChannelContentDetails,
}

#[derive(Debug, Default, Deserialize)]
struct YouTubeChannelContentDetails {
    #[serde(rename = "relatedPlaylists", default)]
    related_playlists: YouTubeRelatedPlaylists,
}

#[derive(Debug, Default, Deserialize)]
struct YouTubeRelatedPlaylists {
    #[serde(default)]
    uploads: Option<String>,
}

impl YouTubeChannelDetailsItem {
    fn content_details_uploads(self) -> Option<String> {
        self.content_details.related_playlists.uploads
    }
}

#[derive(Debug, Deserialize)]
struct YouTubeChannelSnippet {
    #[serde(default)]
    title: String,
    #[serde(default)]
    description: String,
    #[serde(rename = "customUrl", default)]
    custom_url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct YouTubePlaylistItemsResponse {
    #[serde(default)]
    items: Vec<YouTubePlaylistItem>,
}

#[derive(Debug, Deserialize)]
struct YouTubePlaylistItem {
    snippet: YouTubePlaylistSnippet,
    #[serde(rename = "contentDetails", default)]
    content_details: YouTubePlaylistContentDetails,
}

#[derive(Debug, Default, Deserialize)]
struct YouTubePlaylistContentDetails {
    #[serde(rename = "videoId", default)]
    video_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct YouTubePlaylistSnippet {
    #[serde(default)]
    title: String,
    #[serde(default)]
    description: String,
    #[serde(rename = "publishedAt", default)]
    published_at: String,
    #[serde(rename = "channelTitle", default)]
    channel_title: String,
}

impl YouTubeClient {
    pub fn from_env() -> Option<Self> {
        let key = std::env::var("YOUTUBE_API_KEY").ok()?;
        Self::new(key)
    }

    pub fn new(api_key: impl Into<String>) -> Option<Self> {
        let key = api_key.into().trim().to_string();
        if key.trim().is_empty() {
            return None;
        }
        Some(Self {
            api_key: Arc::<str>::from(key),
            http: Client::builder()
                .timeout(Duration::from_secs(8))
                .user_agent("Vozen-Helper/1.0 (+https://vozen.org)")
                .build()
                .expect("valid YouTube HTTP client"),
        })
    }

    pub fn is_configured(&self) -> bool {
        !self.api_key.is_empty()
    }

    /// Search public videos through the official YouTube Data API. The
    /// caller supplies a bounded result count; arbitrary URLs are never
    /// fetched and non-video resources are excluded from the response.
    pub async fn search_videos(
        &self,
        query: &str,
        max_results: usize,
    ) -> anyhow::Result<Vec<YouTubeSearchResult>> {
        let query = query.trim();
        if !(1..=128).contains(&query.len()) {
            anyhow::bail!("invalid_youtube_search_query");
        }
        let max_results = max_results.clamp(1, 5).to_string();
        let response = self
            .http
            .get("https://www.googleapis.com/youtube/v3/search")
            .query(&[
                ("part", "snippet"),
                ("q", query),
                ("type", "video"),
                ("maxResults", max_results.as_str()),
                ("key", self.api_key.as_ref()),
            ])
            .send()
            .await?;
        let status = response.status();
        if !status.is_success() {
            anyhow::bail!("youtube_api_error:{status}");
        }
        let payload: YouTubeSearchResponse = bounded_provider_json(response).await?;
        Ok(payload
            .items
            .into_iter()
            .filter_map(|item| {
                let id = item.id.video_id?;
                Some(YouTubeSearchResult {
                    url: format!("https://www.youtube.com/watch?v={id}"),
                    id,
                    title: item.snippet.title,
                    description: item.snippet.description,
                    channel_title: item.snippet.channel_title,
                })
            })
            .collect())
    }

    /// Resolve one public channel by its stable YouTube channel ID.
    ///
    /// URLs, handles and arbitrary search terms are deliberately rejected so
    /// this endpoint cannot become an unrestricted proxy or SSRF primitive.
    pub async fn channel(&self, channel_id: &str) -> anyhow::Result<Option<YouTubeChannel>> {
        if !valid_channel_id(channel_id) {
            anyhow::bail!("invalid_youtube_channel_id");
        }
        let response = self
            .http
            .get("https://www.googleapis.com/youtube/v3/channels")
            .query(&[
                ("part", "snippet"),
                ("id", channel_id),
                ("key", self.api_key.as_ref()),
            ])
            .send()
            .await?;
        let status = response.status();
        if !status.is_success() {
            // Do not include Google's body: it can contain request details
            // and should never be reflected through the panel API.
            anyhow::bail!("youtube_api_error:{status}");
        }
        let payload = bounded_provider_json::<YouTubeChannelsResponse>(response).await?;
        Ok(payload.items.into_iter().next().map(|item| YouTubeChannel {
            id: item.id,
            title: item.snippet.title,
            description: item.snippet.description,
            custom_url: item.snippet.custom_url,
        }))
    }

    /// Returns the newest public video through the channel's official uploads
    /// playlist. This costs a fraction of the quota used by `search.list` and
    /// still returns only one bounded result.
    pub async fn latest_video(&self, channel_id: &str) -> anyhow::Result<Option<YouTubeVideo>> {
        if !valid_channel_id(channel_id) {
            anyhow::bail!("invalid_youtube_channel_id");
        }
        let response = self
            .http
            .get("https://www.googleapis.com/youtube/v3/channels")
            .query(&[
                ("part", "contentDetails"),
                ("id", channel_id),
                ("key", self.api_key.as_ref()),
            ])
            .send()
            .await?;
        let status = response.status();
        if !status.is_success() {
            anyhow::bail!("youtube_api_error:{status}");
        }
        let uploads = bounded_provider_json::<YouTubeChannelDetailsResponse>(response)
            .await?
            .items
            .into_iter()
            .next()
            .and_then(|item| item.content_details_uploads());
        let Some(uploads_playlist_id) = uploads else {
            return Ok(None);
        };
        let response = self
            .http
            .get("https://www.googleapis.com/youtube/v3/playlistItems")
            .query(&[
                ("part", "snippet,contentDetails"),
                ("playlistId", uploads_playlist_id.as_str()),
                ("maxResults", "1"),
                ("key", self.api_key.as_ref()),
            ])
            .send()
            .await?;
        let status = response.status();
        if !status.is_success() {
            anyhow::bail!("youtube_api_error:{status}");
        }
        let payload = bounded_provider_json::<YouTubePlaylistItemsResponse>(response).await?;
        Ok(payload.items.into_iter().find_map(|item| {
            let id = item.content_details.video_id?;
            Some(YouTubeVideo {
                url: format!("https://www.youtube.com/watch?v={id}"),
                id,
                title: item.snippet.title,
                description: item.snippet.description,
                published_at: item.snippet.published_at,
                channel_title: item.snippet.channel_title,
            })
        }))
    }
}

fn valid_channel_id(value: &str) -> bool {
    (3..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    // A local HTTP boundary exercises the real client without provider secrets.
    fn serve_once(response: String) -> (SocketAddr, std::thread::JoinHandle<String>) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let task = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut request = Vec::new();
            let mut buffer = [0; 4096];
            loop {
                let count = stream.read(&mut buffer).unwrap();
                if count == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..count]);
                if let Some(end) = request.windows(4).position(|part| part == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&request[..end]).to_ascii_lowercase();
                    let length = headers
                        .lines()
                        .find_map(|line| line.strip_prefix("content-length:"))
                        .and_then(|value| value.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    if request.len() >= end + 4 + length {
                        break;
                    }
                }
            }
            // Oversize-response tests deliberately close the connection early.
            let _ = stream.write_all(response.as_bytes());
            String::from_utf8(request).unwrap()
        });
        (address, task)
    }

    fn json_response(body: &str) -> String {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    }

    #[tokio::test]
    async fn tiktok_client_accepts_official_success_and_rejects_api_errors() {
        for (code, expected) in [("ok", true), ("access_token_invalid", false)] {
            let videos = (0..25)
                .map(|id| serde_json::json!({"id":id.to_string(), "title":"Olá 🦀"}))
                .collect::<Vec<_>>();
            let body =
                serde_json::json!({"data":{"videos":videos},"error":{"code":code}}).to_string();
            let (address, server) = serve_once(json_response(&body));
            let mut client =
                TikTokClient::new("test-token", format!("http://localhost:{}", address.port()))
                    .unwrap();
            client.http = Client::builder().no_proxy().build().unwrap();
            let result = client.latest_videos().await;
            if expected {
                let videos = result.unwrap();
                assert_eq!(videos.len(), 20);
                assert_eq!(videos[0].title, "Olá 🦀");
            } else {
                assert!(result.unwrap_err().to_string().contains(code));
            }
            let request = server.join().unwrap();
            assert!(request.starts_with("POST /v2/video/list/?fields="));
            assert!(request.contains("\"max_count\":20"));
        }
    }

    #[tokio::test]
    async fn provider_json_limit_rejects_declared_and_chunked_oversize_responses() {
        let chunk = "x".repeat(MAX_PROVIDER_JSON_BYTES + 1);
        for response in [
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                chunk.len()
            ),
            format!(
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n{chunk}\r\n0\r\n\r\n",
                chunk.len()
            ),
        ] {
            let (address, server) = serve_once(response);
            let response = Client::builder()
                .no_proxy()
                .build()
                .unwrap()
                .get(format!("http://{address}"))
                .send()
                .await
                .unwrap();
            let error = bounded_provider_json::<serde_json::Value>(response)
                .await
                .unwrap_err();
            assert_eq!(error.to_string(), "provider_response_too_large");
            server.join().unwrap();
        }
    }

    #[tokio::test]
    async fn rss_client_pins_dns_and_does_not_follow_redirects() {
        let (address, server) = serve_once("HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1/private\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into());
        let url = Url::parse(&format!("http://feed.invalid:{}/rss", address.port())).unwrap();
        // .invalid cannot resolve: success proves the client uses only these answers.
        let response = feed_http_client(&url, &[address])
            .unwrap()
            .get(url)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::FOUND);
        assert!(server.join().unwrap().contains("host: feed.invalid:"));
    }

    #[tokio::test]
    async fn rss_rejects_private_literals_before_connecting() {
        for url in [
            "http://127.0.0.1/rss",
            "http://[::1]/rss",
            "http://[::ffff:127.0.0.1]/rss",
            "http://100.64.0.1/rss",
            "http://224.0.0.1/rss",
            "file:///etc/passwd",
            "http://user:pass@example.com",
        ] {
            assert!(validate_feed_url(url).await.is_err(), "{url}");
        }
        for address in [
            "::ffff:10.0.0.1",
            "::ffff:169.254.169.254",
            "198.18.0.1",
            "240.0.0.1",
            "64:ff9b::7f00:1",
        ] {
            assert!(private_or_local(address.parse().unwrap()), "{address}");
        }
        for address in ["8.8.8.8", "2606:4700:4700::1111"] {
            assert!(!private_or_local(address.parse().unwrap()), "{address}");
        }
    }

    #[test]
    fn stripe_signature_extreme_timestamps_are_rejected_without_overflow() {
        let client =
            StripeConnectClient::new("sk_test_123456789012345", "whsec_123456789012345").unwrap();
        for timestamp in [i64::MIN, i64::MAX] {
            assert!(!client.verify_webhook(b"{}", &format!("t={timestamp},v1=invalid"), 1000));
        }
    }

    #[test]
    fn provider_flag_parser_is_case_insensitive_and_trimmed() {
        assert!(env_flag_value_is_true(Some(" true ")));
        assert!(env_flag_value_is_true(Some("TRUE")));
        assert!(!env_flag_value_is_true(Some("false")));
        assert!(!env_flag_value_is_true(Some("1")));
        assert!(!env_flag_value_is_true(None));
    }

    #[test]
    fn provider_flag_aliases_keep_primary_false_as_a_hard_gate() {
        assert!(first_env_flag_is_true_from_values(&[
            Some("true"),
            Some("false"),
        ]));
        assert!(!first_env_flag_is_true_from_values(&[
            Some("false"),
            Some("true"),
        ]));
        assert!(first_env_flag_is_true_from_values(&[None, Some(" true ")]));
        assert!(!first_env_flag_is_true_from_values(&[None, None]));
    }

    fn first_env_flag_is_true_from_values(values: &[Option<&str>]) -> bool {
        values
            .iter()
            .find_map(|value| *value)
            .is_some_and(|value| env_flag_value_is_true(Some(value)))
    }

    #[test]
    fn youtube_payload_uses_official_camel_case_fields() {
        let details: YouTubeChannelDetailsResponse = serde_json::from_value(serde_json::json!({
            "items": [{
                "contentDetails": {"relatedPlaylists": {"uploads": "UU123"}}
            }]
        }))
        .expect("channel details payload should decode");
        assert_eq!(
            details
                .items
                .into_iter()
                .next()
                .unwrap()
                .content_details_uploads(),
            Some("UU123".to_string())
        );

        let playlist: YouTubePlaylistItemsResponse = serde_json::from_value(serde_json::json!({
            "items": [{
                "snippet": {
                    "title": "Video",
                    "description": "Description",
                    "publishedAt": "2026-08-02T12:00:00Z",
                    "channelTitle": "Vozen"
                },
                "contentDetails": {"videoId": "abc123"}
            }]
        }))
        .expect("playlist item payload should decode");
        let item = playlist.items.into_iter().next().unwrap();
        assert_eq!(item.content_details.video_id.as_deref(), Some("abc123"));
        assert_eq!(item.snippet.channel_title, "Vozen");
        assert_eq!(item.snippet.published_at, "2026-08-02T12:00:00Z");
    }

    #[test]
    fn official_search_payloads_are_bounded_and_decode_video_channels() {
        let youtube: YouTubeSearchResponse = serde_json::from_value(serde_json::json!({
            "items": [{
                "id": {"kind": "youtube#video", "videoId": "abc123"},
                "snippet": {
                    "title": "A video",
                    "description": "Description",
                    "publishedAt": "2026-08-02T12:00:00Z",
                    "channelTitle": "Vozen"
                }
            }, {
                "id": {"kind": "youtube#channel", "channelId": "ignored"},
                "snippet": {"title": "Not a video"}
            }]
        }))
        .expect("YouTube search payload should decode");
        let videos = youtube
            .items
            .into_iter()
            .filter_map(|item| {
                let id = item.id.video_id?;
                Some(YouTubeSearchResult {
                    id: id.clone(),
                    title: item.snippet.title,
                    description: item.snippet.description,
                    url: format!("https://www.youtube.com/watch?v={id}"),
                    channel_title: item.snippet.channel_title,
                })
            })
            .collect::<Vec<_>>();
        assert_eq!(videos.len(), 1);
        assert_eq!(videos[0].url, "https://www.youtube.com/watch?v=abc123");

        let twitch: TwitchSearchChannelsResponse = serde_json::from_value(serde_json::json!({
            "data": [{
                "broadcaster_login": "vozen",
                "display_name": "Vozen",
                "game_name": "Just Chatting",
                "title": "Welcome",
                "is_live": true
            }]
        }))
        .expect("Twitch search payload should decode");
        assert_eq!(twitch.data[0].broadcaster_login, "vozen");
        assert!(twitch.data[0].is_live);
    }

    #[test]
    fn youtube_channel_id_validation_rejects_urls() {
        assert!(valid_channel_id("UC_abc-123"));
        assert!(!valid_channel_id("https://youtube.com/@vozen"));
        assert!(!valid_channel_id(""));
    }

    #[test]
    fn bluesky_handles_are_normalized_and_bounded() {
        assert_eq!(
            normalize_bluesky_handle("  @Example.com ").unwrap(),
            "example.com"
        );
        assert!(normalize_bluesky_handle("https://bsky.app/profile/example.com").is_err());
        assert!(normalize_bluesky_handle(".invalid").is_err());
        assert!(normalize_bluesky_handle("invalid..handle").is_err());
        assert!(normalize_bluesky_handle(&"a".repeat(254)).is_err());
    }

    #[test]
    fn tiktok_display_payload_uses_official_fields_and_is_bounded() {
        let payload: TikTokVideoResponse = serde_json::from_value(serde_json::json!({
            "data": {"videos": [{
                "id": "734",
                "title": "Hello",
                "video_description": "A short update",
                "create_time": 1720000000,
                "share_url": "https://www.tiktok.com/@vozen/video/734",
                "embed_link": "https://www.tiktok.com/player/v1/734"
            }]},
            "error": {"code": "ok", "message": ""}
        }))
        .expect("TikTok Display payload should decode");
        assert_eq!(payload.data.videos.len(), 1);
        assert_eq!(payload.data.videos[0].id, "734");
        assert!(TikTokClient::new("token", "https://open.tiktokapis.com").is_some());
        assert!(TikTokClient::new("", "https://open.tiktokapis.com").is_none());
    }

    #[test]
    fn instagram_graph_payload_is_bounded_and_requires_numeric_user_id() {
        let payload: InstagramMediaResponse = serde_json::from_value(serde_json::json!({
            "data": [{
                "id": "media-1",
                "caption": "Launch",
                "media_type": "IMAGE",
                "media_url": "https://cdn.example/media.jpg",
                "permalink": "https://www.instagram.com/p/media-1/",
                "timestamp": "2026-08-04T00:00:00+0000"
            }]
        }))
        .expect("Meta media payload should decode");
        assert_eq!(payload.data.len(), 1);
        assert_eq!(payload.data[0].id, "media-1");
        assert!(
            InstagramClient::new(
                "token",
                "17841400000000000",
                "https://graph.facebook.com/v22.0"
            )
            .is_some()
        );
        assert!(
            InstagramClient::new("token", "creator-name", "https://graph.facebook.com/v22.0")
                .is_none()
        );
    }

    #[test]
    fn kick_public_payload_is_parsed_without_accepting_insecure_clients() {
        let payload = serde_json::json!({
            "data": [{
                "slug": "vozen",
                "stream": {
                    "id": 42,
                    "is_live": true,
                    "stream_title": "Building safely",
                    "category": {"name": "Software Development"},
                    "start_time": "2026-08-04T12:00:00Z"
                }
            }]
        });
        let channel = payload["data"].as_array().unwrap().first().unwrap();
        assert_eq!(channel["slug"], "vozen");
        assert_eq!(channel["stream"]["is_live"], true);
        assert!(KickClient::new("token", "https://api.kick.com/public/v1").is_some());
        assert!(KickClient::new("token", "http://example.com").is_none());
    }

    #[test]
    fn stripe_webhook_signature_is_time_bounded_and_constant_time_checked() {
        let client =
            StripeConnectClient::new("sk_test_123456789012345", "whsec_123456789012345").unwrap();
        let payload = br#"{"id":"evt_1"}"#;
        let timestamp = 1_000_i64;
        let mut mac = Hmac::<Sha256>::new_from_slice(b"whsec_123456789012345").unwrap();
        mac.update(timestamp.to_string().as_bytes());
        mac.update(b".");
        mac.update(payload);
        let signature = format!(
            "t={timestamp},v1={}",
            hex::encode(mac.finalize().into_bytes())
        );
        assert!(client.verify_webhook(payload, &signature, timestamp));
        assert!(!client.verify_webhook(payload, &signature, timestamp + 301));
    }

    #[test]
    fn ethereum_recovery_matches_external_personal_sign_vector() {
        // ethers.js v3 Wallet.verifyMessage example: https://docs.ethers.org/v3/api-wallet.html
        let signature = concat!(
            "ddd0a7290af9526056b4e35a077b9a11b513aa0028ec6c9880948544508f3c63",
            "265e99e47ad31bb2cab9646c504576b3abc6939a1710afc08cbf3034d73214b8",
            "1c"
        );
        let address = "0x14791697260e4c9a71f18484c9f997b308e59325";
        assert_eq!(
            recover_eth_address("hello world", signature).unwrap(),
            address
        );
        let prefixed = format!("0x{signature}");
        assert_eq!(
            recover_eth_address("hello world", &prefixed).unwrap(),
            address
        );
        let raw_recovery = format!("{}01", &signature[..128]);
        assert_eq!(
            recover_eth_address("hello world", &raw_recovery).unwrap(),
            address
        );
        assert_ne!(
            recover_eth_address("hello world!", signature).unwrap(),
            address
        );
        let high_s = concat!(
            "ddd0a7290af9526056b4e35a077b9a11b513aa0028ec6c9880948544508f3c63",
            "d9a1661b852ce44d35469b93afba894b0ee8494c9837f07b33132e57f9042c89",
            "1b"
        );
        assert!(recover_eth_address("hello world", high_s).is_err());
        for invalid in [
            "zz".to_owned(),
            "00".repeat(65),
            format!("{}02", &signature[..128]),
            signature[..128].to_owned(),
        ] {
            assert!(recover_eth_address("hello world", &invalid).is_err());
        }
    }

    #[test]
    fn siwe_rejects_wrong_context_and_recovers_ethereum_address() {
        use k256::ecdsa::SigningKey;

        let verifier = SiweVerifier::new(
            "admin.example.com",
            "https://admin.example.com/",
            "01234567890123456789012345678901",
        )
        .expect("valid SIWE verifier");
        let key_bytes: [u8; 32] =
            hex::decode("4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318")
                .unwrap()
                .try_into()
                .unwrap();
        let signing_key = SigningKey::from_bytes((&key_bytes).into()).unwrap();
        let address = eth_address_from_key(signing_key.verifying_key());
        let now = Utc::now();
        let message = format!(
            "admin.example.com wants you to sign in with your Ethereum account:\n{}\n\nVozen wallet verification\n\nURI: https://admin.example.com/\nVersion: 1\nChain ID: 1\nNonce: ABCD1234\nIssued At: {}\nExpiration Time: {}",
            address,
            now.to_rfc3339(),
            (now + chrono::Duration::minutes(5)).to_rfc3339()
        );
        let mut payload = format!("\x19Ethereum Signed Message:\n{}", message.len()).into_bytes();
        payload.extend_from_slice(message.as_bytes());
        let (signature, recovery) =
            signing_key.sign_prehash_recoverable(&Keccak256::digest(payload));
        let encoded = format!(
            "0x{}{:02x}",
            hex::encode(signature.to_bytes()),
            recovery.to_byte() + 27
        );
        let claims = verifier
            .verify(&message, &encoded, "ABCD1234", now)
            .expect("valid SIWE message");
        assert_eq!(claims.address, address);
        assert!(
            verifier
                .verify(&message, &encoded, "WRONG123", now)
                .is_err()
        );
    }

    #[test]
    fn siwe_nonces_are_eip4361_alphanumeric() {
        let verifier = SiweVerifier::new(
            "example.test",
            "https://example.test/",
            "12345678901234567890123456789012",
        )
        .expect("valid verifier");
        let nonce = verifier.issue_nonce();
        assert!((8..=128).contains(&nonce.len()));
        assert!(nonce.bytes().all(|byte| byte.is_ascii_alphanumeric()));
    }

    #[test]
    fn coingecko_ids_and_currency_are_bounded() {
        assert_eq!(normalize_coingecko_id(" Bitcoin ").unwrap(), "bitcoin");
        assert!(normalize_coingecko_id("bitcoin/usd").is_err());
        assert!(normalize_coingecko_id("-bitcoin").is_err());
        assert!(normalize_currency("EUR").is_ok());
        assert!(normalize_currency("u$ d").is_err());
    }

    #[test]
    fn rpc_identifiers_are_bounded() {
        assert_eq!(normalize_network(" Ethereum ").unwrap(), "ethereum");
        assert!(normalize_network("mainnet").is_err());
        assert!(validate_rpc_url("http://rpc.example").is_err());
        assert!(validate_rpc_url("https://rpc.example/key?secret=1").is_err());
    }

    #[test]
    fn tiktok_token_cipher_round_trips_without_deterministic_ciphertext() {
        let cipher = TokenCipher::new("a-long-production-session-secret").unwrap();
        let first = cipher.seal("token-value").unwrap();
        let second = cipher.seal("token-value").unwrap();
        assert_ne!(first, second);
        assert_eq!(cipher.open(&first).unwrap(), "token-value");
        assert_eq!(cipher.open(&second).unwrap(), "token-value");
        assert!(
            TokenCipher::new("another-production-session-secret")
                .unwrap()
                .open(&first)
                .is_err()
        );
    }

    #[test]
    fn tiktok_authorization_url_uses_official_endpoint_and_minimal_scopes() {
        let oauth = TikTokOAuthClient::new(
            "client-key",
            "client-secret",
            "https://api.example.com/rust/api/providers/tiktok/oauth/callback",
            "https://www.tiktok.com/v2/auth/authorize/",
            "https://open.tiktokapis.com/v2/oauth/token/",
        )
        .unwrap();
        let url = Url::parse(&oauth.authorization_url("signed-state").unwrap()).unwrap();
        assert_eq!(url.host_str(), Some("www.tiktok.com"));
        let query: HashMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(
            query.get("client_key").map(String::as_str),
            Some("client-key")
        );
        assert_eq!(
            query.get("scope").map(String::as_str),
            Some("user.info.basic,video.list")
        );
        assert_eq!(query.get("state").map(String::as_str), Some("signed-state"));
        assert_eq!(query.get("response_type").map(String::as_str), Some("code"));
    }

    #[test]
    fn rss_parser_supports_rss_and_atom() {
        let rss = br#"<?xml version="1.0"?><rss><channel><title>Vozen News</title><item><guid>post-1</guid><title>First post</title><description>Hello &amp; welcome</description><link>https://example.com/post-1</link><pubDate>2026-08-02T12:00:00Z</pubDate></item></channel></rss>"#;
        let parsed = parse_feed(rss)
            .expect("RSS should parse")
            .expect("RSS has an item");
        assert_eq!(parsed.title, "Vozen News");
        let item = parsed.latest.expect("RSS latest item");
        assert_eq!(item.id, "post-1");
        assert_eq!(item.title, "First post");
        assert_eq!(item.description, "Hello & welcome");
        assert_eq!(item.url, "https://example.com/post-1");

        let atom = br#"<feed xmlns="http://www.w3.org/2005/Atom"><title>Atom Updates</title><entry><id>tag:example.com,2026:2</id><title>Atom entry</title><summary>Summary</summary><link href="https://example.com/atom-2"/><updated>2026-08-02T13:00:00Z</updated></entry></feed>"#;
        let parsed = parse_feed(atom)
            .expect("Atom should parse")
            .expect("Atom has an entry");
        assert_eq!(parsed.title, "Atom Updates");
        let item = parsed.latest.expect("Atom latest item");
        assert_eq!(item.id, "tag:example.com,2026:2");
        assert_eq!(item.url, "https://example.com/atom-2");
    }

    #[test]
    fn rss_private_address_check_rejects_local_ranges() {
        assert!(private_or_local("127.0.0.1".parse().unwrap()));
        assert!(private_or_local("10.0.0.1".parse().unwrap()));
        assert!(private_or_local("192.168.1.1".parse().unwrap()));
        assert!(private_or_local("::1".parse().unwrap()));
        assert!(!private_or_local("1.1.1.1".parse().unwrap()));
    }

    #[test]
    fn rss_message_renderer_matches_bounded_discord_contract() {
        let item = RssItem {
            id: "post-1".into(),
            title: "A new post".into(),
            description: "Details".into(),
            url: "https://example.com/post-1".into(),
            published_at: "2026-08-02T12:00:00Z".into(),
            feed_title: "Vozen News".into(),
        };
        let rendered = format_rss_message("{feed}: {title} — {url}", "", &item);
        assert_eq!(
            rendered,
            "Vozen News: A new post — https://example.com/post-1"
        );
        let bounded = format_rss_message(&"x".repeat(3_000), "@everyone", &item);
        assert_eq!(bounded.chars().count(), 2_000);
        assert!(bounded.starts_with("@everyone "));
    }

    #[test]
    fn youtube_message_renderer_matches_bounded_discord_contract() {
        let video = YouTubeVideo {
            id: "video-1".into(),
            title: "A new video".into(),
            description: "Details".into(),
            url: "https://youtube.com/watch?v=video-1".into(),
            published_at: "2026-08-02T12:00:00Z".into(),
            channel_title: "Vozen".into(),
        };
        let rendered = format_youtube_message("{channel}: {title} — {url}", "", &video, "UC123");
        assert_eq!(
            rendered,
            "Vozen: A new video — https://youtube.com/watch?v=video-1"
        );
        let bounded = format_youtube_message(&"x".repeat(3_000), "@everyone", &video, "UC123");
        assert_eq!(bounded.chars().count(), 2_000);
        assert!(bounded.starts_with("@everyone "));
    }

    #[test]
    fn twitch_message_renderer_matches_bounded_discord_contract() {
        let rendered = format_twitch_message(
            "{broadcaster} is live! {url} ({stream_id})",
            "",
            "vozen",
            "stream-1",
            "2026-08-05T12:00:00Z",
        );
        assert_eq!(
            rendered,
            "vozen is live! https://twitch.tv/vozen (stream-1)"
        );
        let bounded =
            format_twitch_message(&"x".repeat(3_000), "@everyone", "vozen", "stream-1", "now");
        assert_eq!(bounded.chars().count(), 2_000);
        assert!(bounded.starts_with("@everyone "));
    }
}

pub const MODULES: &[Capability] = &[
    Capability::Core,
    Capability::Studio,
    Capability::Security,
    Capability::Support,
    Capability::Events,
    Capability::Community,
    Capability::Automate,
    Capability::Insights,
];

type HmacSha256 = Hmac<Sha256>;

// Entitlements can change while a dashboard session is open (for example when
// a Premium seat is assigned to the current guild). Keep the small in-memory
// cache for request bursts, but never let an old Free snapshot live for the
// entire process lifetime.
const ENTITLEMENT_CACHE_TTL: chrono::Duration = chrono::Duration::seconds(30);

#[derive(Clone)]
pub struct EntitlementClient {
    endpoint: String,
    secret: String,
    http: Client,
    cache: Arc<Mutex<HashMap<String, EntitlementSnapshot>>>,
}

#[derive(Debug, Deserialize)]
struct CentralResponse {
    subject_id: String,
    plan: String,
    guild_limit: u16,
    active: bool,
    expires_at_ms: Option<i64>,
    version: i64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PremiumSeats {
    pub guild_premium: bool,
    pub pass_active: bool,
    pub seats: i64,
    pub used: i64,
}

impl EntitlementClient {
    pub async fn premium_seats(
        &self,
        user: &str,
        guild: &str,
        activate: bool,
    ) -> anyhow::Result<PremiumSeats> {
        let endpoint = self
            .endpoint
            .strip_suffix("/resolve")
            .ok_or_else(|| anyhow::anyhow!("invalid entitlement endpoint"))?;
        let body = serde_json::json!({"subject_id": user, "guild_id": guild, "operation": if activate { "activate" } else { "status" }});
        let bytes = serde_json::to_vec(&body)?;
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let nonce = uuid::Uuid::new_v4().to_string();
        let body_hash = URL_SAFE_NO_PAD.encode(Sha256::digest(&bytes));
        let mut mac = HmacSha256::new_from_slice(self.secret.as_bytes())?;
        mac.update(format!("{timestamp}\n{nonce}\n{body_hash}").as_bytes());
        let signature = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        let response = self
            .http
            .post(format!("{endpoint}/seats"))
            .header("x-vozen-timestamp", timestamp.to_string())
            .header("x-vozen-nonce", nonce)
            .header("x-vozen-signature", format!("v1={signature}"))
            .json(&body)
            .send()
            .await?;
        if !response.status().is_success() {
            anyhow::bail!("premium activation unavailable or subscription changed");
        }
        let result: PremiumSeats = bounded_provider_json(response).await?;
        if activate {
            self.cache
                .lock()
                .map_err(|_| anyhow::anyhow!("cache unavailable"))?
                .remove(&Self::cache_key(user, Some(guild)));
        }
        Ok(result)
    }
    pub fn new(endpoint: Option<String>, secret: Option<String>) -> Option<Self> {
        Some(Self {
            endpoint: endpoint?,
            secret: secret?,
            http: Client::builder()
                .timeout(Duration::from_secs(3))
                .build()
                .expect("valid entitlement HTTP client"),
            cache: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub async fn resolve(
        &self,
        subject_id: &str,
        guild_id: Option<&str>,
    ) -> anyhow::Result<EntitlementSnapshot> {
        if let Some(snapshot) = self.cached(subject_id, guild_id)
            && snapshot.active
            && snapshot
                .expires_at
                .is_none_or(|expires_at| expires_at > Utc::now())
        {
            return Ok(snapshot);
        }
        let body = serde_json::json!({"subject_id": subject_id, "guild_id": guild_id});
        let bytes = serde_json::to_vec(&body)?;
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let nonce = uuid::Uuid::new_v4().to_string();
        let body_hash = URL_SAFE_NO_PAD.encode(Sha256::digest(&bytes));
        let mut mac = HmacSha256::new_from_slice(self.secret.as_bytes())?;
        mac.update(format!("{timestamp}\n{nonce}\n{body_hash}").as_bytes());
        let signature = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        let response = self
            .http
            .post(&self.endpoint)
            .header("x-vozen-timestamp", timestamp.to_string())
            .header("x-vozen-nonce", &nonce)
            .header("x-vozen-signature", format!("v1={signature}"))
            .json(&body)
            .send()
            .await?;
        if !response.status().is_success() {
            anyhow::bail!("central entitlement service returned {}", response.status());
        }
        let central: CentralResponse = bounded_provider_json(response).await?;
        let plan = match central.plan.as_str() {
            "plus" => Plan::Plus,
            "premium" => Plan::Premium {
                guild_limit: central.guild_limit,
            },
            _ => Plan::Free,
        };
        let snapshot = EntitlementSnapshot {
            product: "vozen-helper".into(),
            subject_id: central.subject_id,
            plan,
            active: central.active,
            version: central.version.try_into().unwrap_or_default(),
            expires_at: central
                .expires_at_ms
                .and_then(chrono::DateTime::from_timestamp_millis),
            fetched_at: Utc::now(),
        };
        self.cache
            .lock()
            .expect("entitlement cache poisoned")
            .insert(Self::cache_key(subject_id, guild_id), snapshot.clone());
        Ok(snapshot)
    }

    fn cache_key(subject_id: &str, guild_id: Option<&str>) -> String {
        format!("{subject_id}:{}", guild_id.unwrap_or("user"))
    }

    pub fn cached(&self, subject_id: &str, guild_id: Option<&str>) -> Option<EntitlementSnapshot> {
        let key = Self::cache_key(subject_id, guild_id);
        let mut cache = self.cache.lock().ok()?;
        let snapshot = cache.get(&key)?.clone();
        if Utc::now().signed_duration_since(snapshot.fetched_at) <= ENTITLEMENT_CACHE_TTL {
            Some(snapshot)
        } else {
            cache.remove(&key);
            None
        }
    }
}

/// Bounded persistent scheduler. It never runs unbounded work on the gateway
/// task: each tick claims at most 100 due rows and removes them only after the
/// dispatch boundary has been reached.
pub fn start_scheduler(store: Store) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        let mut last_retention = Instant::now() - Duration::from_secs(86_401);
        loop {
            interval.tick().await;
            if last_retention.elapsed() >= Duration::from_secs(86_400) {
                match store.prune_retention(chrono::Utc::now().timestamp_millis()) {
                    Ok(summary) => tracing::info!(?summary, "retention sweep completed"),
                    Err(error) => tracing::error!(%error, "retention sweep failed"),
                }
                last_retention = Instant::now();
            }
            match store.due_scheduled_actions(chrono::Utc::now().timestamp_millis(), 100) {
                Ok(actions) => {
                    for (id, guild_id, kind, target_id, _payload) in actions {
                        tracing::info!(%id, %guild_id, %kind, %target_id, "dispatching scheduled helper action");
                        if let Err(error) = store.delete_scheduled_action(id) {
                            tracing::error!(%error, %id, "failed to ack scheduled action");
                        }
                    }
                }
                Err(error) => tracing::error!(%error, "scheduler tick failed"),
            }
        }
    })
}
