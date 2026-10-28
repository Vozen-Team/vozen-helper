//! Fresh Discord authority checks before human-requested moderation side effects.
use helper_core::manual_moderation::Authority;
use reqwest::Client;
use serde_json::Value;
use std::{collections::HashMap, time::Duration};

pub(super) async fn allowed(
    http: &serenity::http::Http,
    guild: u64,
    actor: u64,
    target: u64,
    action: &str,
    restored_roles: &[String],
) -> bool {
    let Ok(client) = Client::builder()
        .timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()
    else {
        return false;
    };
    tokio::time::timeout(
        Duration::from_secs(8),
        allowed_at(
            &client,
            "https://discord.com/api/v10",
            http.token(),
            guild,
            actor,
            target,
            action,
            restored_roles,
        ),
    )
    .await
    .ok()
    .and_then(Result::ok)
    .unwrap_or(false)
}

async fn read(client: &Client, auth: &str, url: &str) -> Result<Value, ()> {
    client
        .get(url)
        .header(reqwest::header::AUTHORIZATION, auth)
        .send()
        .await
        .map_err(|_| ())?
        .error_for_status()
        .map_err(|_| ())?
        .json()
        .await
        .map_err(|_| ())
}

#[allow(clippy::too_many_arguments)]
async fn allowed_at(
    client: &Client,
    base: &str,
    auth: &str,
    guild: u64,
    actor: u64,
    target: u64,
    action: &str,
    restored_roles: &[String],
) -> Result<bool, ()> {
    let guild_value = read(client, auth, &format!("{base}/guilds/{guild}")).await?;
    let owner_id = guild_value["owner_id"]
        .as_str()
        .and_then(|id| id.parse::<u64>().ok())
        .filter(|id| *id > 0)
        .ok_or(())?;
    let roles = read(client, auth, &format!("{base}/guilds/{guild}/roles")).await?;
    let roles = roles
        .as_array()
        .ok_or(())?
        .iter()
        .map(|role| {
            let id = role["id"]
                .as_str()
                .and_then(|id| id.parse::<u64>().ok())
                .ok_or(())?;
            let position = role["position"]
                .as_i64()
                .filter(|position| *position >= 0)
                .ok_or(())?;
            let permissions = role["permissions"]
                .as_str()
                .and_then(|bits| bits.parse::<u64>().ok())
                .ok_or(())?;
            Ok((
                id,
                (
                    position,
                    permissions,
                    role["managed"].as_bool().unwrap_or(true),
                ),
            ))
        })
        .collect::<Result<HashMap<_, _>, ()>>()?;
    let member_authority = |member: &Value| -> Result<(i64, u64), ()> {
        let mut top = 0;
        let mut bits = roles.get(&guild).ok_or(())?.1;
        for role in member["roles"].as_array().ok_or(())? {
            let id = role
                .as_str()
                .and_then(|id| id.parse::<u64>().ok())
                .ok_or(())?;
            let (position, permissions, _) = roles.get(&id).ok_or(())?;
            top = top.max(*position);
            bits |= permissions;
        }
        Ok((top, bits))
    };
    let actor_value = read(
        client,
        auth,
        &format!("{base}/guilds/{guild}/members/{actor}"),
    )
    .await?;
    let (actor_top, actor_permissions) = member_authority(&actor_value)?;
    let bot = read(client, auth, &format!("{base}/users/@me")).await?;
    let bot_id = bot["id"]
        .as_str()
        .and_then(|id| id.parse::<u64>().ok())
        .filter(|id| *id > 0)
        .ok_or(())?;
    let bot = read(
        client,
        auth,
        &format!("{base}/guilds/{guild}/members/{bot_id}"),
    )
    .await?;
    let (bot_top, bot_permissions) = member_authority(&bot)?;
    let response = client
        .get(format!("{base}/guilds/{guild}/members/{target}"))
        .header(reqwest::header::AUTHORIZATION, auth)
        .send()
        .await
        .map_err(|_| ())?;
    let mut target_roles = Vec::new();
    let (target_top, target_administrator) = if response.status() == reqwest::StatusCode::NOT_FOUND
    {
        (None, false)
    } else {
        let member = response
            .error_for_status()
            .map_err(|_| ())?
            .json::<Value>()
            .await
            .map_err(|_| ())?;
        target_roles = member["roles"]
            .as_array()
            .ok_or(())?
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect();
        let (position, permissions) = member_authority(&member)?;
        (Some(position), permissions & 8 != 0)
    };
    let role_authority = helper_core::RoleOfferAuthority {
        actor_is_owner: actor == owner_id,
        actor_permissions,
        actor_top_position: actor_top,
        bot_permissions,
        bot_top_position: bot_top,
    };
    for role in restored_roles
        .iter()
        .filter(|id| !target_roles.contains(id))
    {
        let id = role.parse::<u64>().map_err(|_| ())?;
        let value = roles.get(&id);
        if !helper_core::role_offer_allowed(
            guild,
            id,
            value.map(|value| value.0),
            value.is_none_or(|value| value.2),
            &role_authority,
        ) {
            return Ok(false);
        }
    }
    Ok(helper_core::manual_moderation::allowed(
        action,
        &Authority {
            actor_id: actor,
            target_id: target,
            owner_id,
            actor_permissions,
            actor_top,
            bot_permissions,
            bot_top,
            target_top,
            target_administrator,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Read, Write},
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering},
        },
    };

    #[tokio::test]
    async fn fresh_lookup_distinguishes_absent_target_from_outage_and_checks_hierarchy() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let target_status = Arc::new(AtomicU16::new(200));
        let target_position = Arc::new(AtomicU64::new(4));
        let stop = Arc::new(AtomicBool::new(false));
        let state = (target_status.clone(), target_position.clone(), stop.clone());
        let server = std::thread::spawn(move || {
            while !state.2.load(Ordering::SeqCst) {
                let Ok((mut stream, _)) = listener.accept() else {
                    std::thread::sleep(Duration::from_millis(1));
                    continue;
                };
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut request = [0; 8192];
                let size = stream.read(&mut request).unwrap();
                let request = String::from_utf8_lossy(&request[..size]);
                let path = request.split_whitespace().nth(1).unwrap_or("");
                let (status, body) = match path {
                    "/guilds/1" => (200, serde_json::json!({"owner_id":"9"})),
                    "/users/@me" => (200, serde_json::json!({"id":"8"})),
                    "/guilds/1/roles" => (
                        200,
                        serde_json::json!([
                            {"id":"1","position":0,"managed":false,"permissions":"0"},
                            {"id":"20","position":5,"managed":false,"permissions":"1099780063238"},
                            {"id":"30","position":state.1.load(Ordering::SeqCst),"managed":false,"permissions":"0"},
                            {"id":"40","position":3,"managed":false,"permissions":"0"},
                            {"id":"80","position":10,"managed":false,"permissions":"1099780063238"}
                        ]),
                    ),
                    "/guilds/1/members/2" => (200, serde_json::json!({"roles":["20"]})),
                    "/guilds/1/members/8" => (200, serde_json::json!({"roles":["80"]})),
                    "/guilds/1/members/3" => (
                        state.0.load(Ordering::SeqCst),
                        serde_json::json!({"roles":["30"]}),
                    ),
                    _ => (500, Value::Null),
                };
                let body = body.to_string();
                write!(stream, "HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
            }
        });
        let client = Client::new();
        let checks = async {
            assert_eq!(
                allowed_at(&client, &base, "Bot synthetic", 1, 2, 3, "ban", &[]).await,
                Ok(true)
            );
            assert_eq!(
                allowed_at(
                    &client,
                    &base,
                    "Bot synthetic",
                    1,
                    2,
                    3,
                    "unquarantine",
                    &["40".into()]
                )
                .await,
                Ok(true)
            );
            assert_eq!(
                allowed_at(
                    &client,
                    &base,
                    "Bot synthetic",
                    1,
                    2,
                    3,
                    "unquarantine",
                    &["20".into()]
                )
                .await,
                Ok(false)
            );
            assert_eq!(
                allowed_at(
                    &client,
                    &base,
                    "Bot synthetic",
                    1,
                    2,
                    3,
                    "unquarantine",
                    &["80".into()]
                )
                .await,
                Ok(false)
            );
            target_position.store(5, Ordering::SeqCst);
            assert_eq!(
                allowed_at(&client, &base, "Bot synthetic", 1, 2, 3, "ban", &[]).await,
                Ok(false)
            );
            target_status.store(404, Ordering::SeqCst);
            assert_eq!(
                allowed_at(&client, &base, "Bot synthetic", 1, 2, 3, "ban", &[]).await,
                Ok(true)
            );
            assert_eq!(
                allowed_at(&client, &base, "Bot synthetic", 1, 2, 3, "kick", &[]).await,
                Ok(false)
            );
            target_status.store(503, Ordering::SeqCst);
            assert!(
                allowed_at(&client, &base, "Bot synthetic", 1, 2, 3, "ban", &[])
                    .await
                    .is_err()
            );
        };
        let result = tokio::time::timeout(Duration::from_secs(10), checks).await;
        stop.store(true, Ordering::SeqCst);
        server.join().unwrap();
        result.unwrap();
    }
}
