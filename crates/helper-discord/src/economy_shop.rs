use super::*;
use crate::shop_i18n::text;
use helper_store::{ShopOrder, ShopProduct};
use serenity::all::ComponentInteraction;

pub(super) fn safe(value: &str) -> String {
    value
        .chars()
        .flat_map(|c| {
            if "\\`*_~[]()<>@".contains(c) {
                vec!['\\', c]
            } else {
                vec![c]
            }
        })
        .collect()
}
fn button(item: &ShopProduct) -> CreateButton {
    CreateButton::new(format!("shop:view:{}:{}", item.id, item.version))
        .label(format!("{} · {}", item.name, item.price))
        .style(ButtonStyle::Secondary)
}
pub(super) async fn show(store: &Store, ctx: &Context, command: &CommandInteraction) -> Result<()> {
    let Some(guild) = command.guild_id else {
        return respond(ctx, command, "This command can only be used in a server.").await;
    };
    if !feature_enabled(store, &guild.to_string(), "community.economy", None) {
        return respond(
            ctx,
            command,
            "Economy is disabled in this server. Enable it in the dashboard.",
        )
        .await;
    }
    let items = store.shop_products(&guild.to_string())?;
    let currency = setting_string(store, &guild.to_string(), "community.economy.currency_name")
        .unwrap_or_else(|| private_replies::system_word("credits"));
    let description = if items.is_empty() {
        text(&command.locale, 7).into()
    } else {
        items
            .iter()
            .map(|p| format!("**{}** — {} {}", safe(&p.name), p.price, safe(&currency)))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let rows = items
        .chunks(5)
        .map(|items| CreateActionRow::Buttons(items.iter().map(button).collect()))
        .collect();
    command
        .edit_response(
            ctx,
            EditInteractionResponse::new()
                .embed(
                    CreateEmbed::new()
                        .title(text(&command.locale, 0))
                        .description(description)
                        .colour(0x8ee5d2),
                )
                .components(rows)
                .allowed_mentions(CreateAllowedMentions::new()),
        )
        .await?;
    Ok(())
}
fn result_text(locale: &str, order: &ShopOrder) -> String {
    if order.status == "refunded" {
        return format!(
            "#{} · **{}** · ↩ +{}",
            order.id,
            safe(&order.product_name),
            order.price
        );
    }
    format!(
        "#{} · **{}** · {}",
        order.id,
        safe(&order.product_name),
        text(locale, if order.status == "delivered" { 5 } else { 4 })
    )
}
async fn feedback(ctx: &Context, c: &ComponentInteraction, key: usize) -> Result<()> {
    c.edit_response(ctx, raw_feedback(text(&c.locale, key)).components(vec![]))
        .await?;
    Ok(())
}
pub(super) async fn handle(store: &Store, ctx: &Context, c: &ComponentInteraction) -> Result<()> {
    let Some(guild) = c.guild_id else {
        return feedback(ctx, c, 2).await;
    };
    let g = guild.to_string();
    if !feature_enabled(store, &g, "community.economy", None) {
        return respond_component(
            ctx,
            c,
            "Economy is disabled in this server. Enable it in the dashboard.",
        )
        .await;
    }
    let parts = c.data.custom_id.split(':').collect::<Vec<_>>();
    if parts.as_slice() == ["shop", "cancel"] {
        return feedback(ctx, c, 10).await;
    }
    if !matches!(parts.len(), 4 | 6) {
        return feedback(ctx, c, 2).await;
    }
    let id = parts[2].parse::<i64>().ok();
    let version = parts[3].parse::<i64>().ok();
    let item = store
        .shop_products(&g)?
        .into_iter()
        .find(|p| Some(p.id) == id && Some(p.version) == version);
    let Some(item) = item else {
        return feedback(ctx, c, 2).await;
    };
    let currency = setting_string(store, &g, "community.economy.currency_name")
        .unwrap_or_else(|| private_replies::system_word("credits"));
    if parts[1] == "view" && parts.len() == 4 {
        let confirm = format!(
            "shop:buy:{}:{}:{}:{}",
            item.id, item.version, c.user.id, c.id
        );
        c.edit_response(
            ctx,
            raw_feedback(&format!(
                "**{}**\n{} {}",
                safe(&item.name),
                item.price,
                safe(&currency)
            ))
            .components(vec![CreateActionRow::Buttons(vec![
                CreateButton::new(confirm)
                    .label(text(&c.locale, 1))
                    .style(ButtonStyle::Success),
                CreateButton::new("shop:cancel")
                    .label(text(&c.locale, 9))
                    .style(ButtonStyle::Secondary),
            ])]),
        )
        .await?;
        return Ok(());
    }
    if parts[1] != "buy"
        || parts.len() != 6
        || parts[4] != c.user.id.to_string()
        || parts[5].parse::<u64>().is_err()
    {
        return feedback(ctx, c, 2).await;
    }
    let role = if item.delivery == "role" {
        let role_id = RoleId::new(
            item.role_id
                .as_ref()
                .and_then(|id| id.parse::<u64>().ok())
                .filter(|id| *id > 0)
                .ok_or_else(|| anyhow::anyhow!("invalid shop role"))?,
        );
        let roles = guild.roles(&ctx.http).await?;
        let Some(role) = roles.get(&role_id) else {
            return feedback(ctx, c, 2).await;
        };
        let bot = guild
            .member(&ctx.http, ctx.http.get_current_user().await?.id)
            .await?;
        let top = bot
            .roles
            .iter()
            .filter_map(|id| roles.get(id).map(|r| r.position))
            .max()
            .unwrap_or(0);
        let permissions = bot
            .roles
            .iter()
            .chain(std::iter::once(&RoleId::new(guild.get())))
            .filter_map(|id| roles.get(id))
            .fold(Permissions::empty(), |p, r| p | r.permissions);
        if role.managed
            || role_id.get() == guild.get()
            || role.position >= top
            || !helper_core::shop_role_permissions_safe(role.permissions.bits())
            || !permissions.intersects(Permissions::MANAGE_ROLES | Permissions::ADMINISTRATOR)
        {
            return feedback(ctx, c, 2).await;
        }
        let member = guild.member(&ctx.http, c.user.id).await?;
        if member.roles.contains(&role_id) {
            return feedback(ctx, c, 6).await;
        }
        Some((member, role_id))
    } else {
        None
    };
    let name = c
        .member
        .as_ref()
        .and_then(|m| m.nick.as_deref())
        .or(c.user.global_name.as_deref())
        .unwrap_or(&c.user.name);
    let order = match store.buy_shop_product(
        &g,
        &c.user.id.to_string(),
        name,
        item.id,
        item.version,
        parts[5],
    ) {
        Ok(order) => order,
        Err(error) => {
            return feedback(
                ctx,
                c,
                match error.to_string().as_str() {
                    "shop_insufficient" => 3,
                    "shop_already_owned" => 6,
                    _ => 2,
                },
            )
            .await;
        }
    };
    if order.status == "pending"
        && let Some((member, role_id)) = role
    {
        match member.add_role(&ctx.http, role_id).await {
            Ok(()) => {
                store.resolve_shop_order(&g, order.id, "delivered", "helper")?;
                let mut completed = order;
                completed.status = "delivered".into();
                c.edit_response(
                    ctx,
                    raw_feedback(&result_text(&c.locale, &completed)).components(vec![]),
                )
                .await?;
                return Ok(());
            }
            Err(error) => {
                // A timeout can mean Discord applied the role. Keep the debit and order for staff review.
                warn!(%error,order_id=order.id,"shop role delivery requires review");
                c.edit_response(
                    ctx,
                    raw_feedback(&format!(
                        "{}\n{}",
                        result_text(&c.locale, &order),
                        text(&c.locale, 8)
                    ))
                    .components(vec![]),
                )
                .await?;
                return Ok(());
            }
        }
    }
    c.edit_response(
        ctx,
        raw_feedback(&result_text(&c.locale, &order)).components(vec![]),
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shop_buttons_are_bounded_and_product_markup_is_escaped() {
        let item = ShopProduct {
            id: i64::MAX,
            name: "x".repeat(60),
            price: 1_000_000,
            delivery: "manual".into(),
            role_id: None,
            version: i64::MAX,
        };
        let value = serde_json::to_value(button(&item)).unwrap();
        assert!(value["custom_id"].as_str().unwrap().len() <= 100);
        assert!(value["label"].as_str().unwrap().chars().count() <= 80);
        assert!(
            format!(
                "shop:buy:{}:{}:{}:{}",
                item.id,
                item.version,
                u64::MAX,
                u64::MAX
            )
            .len()
                <= 100
        );
        assert_eq!(safe("[x](url) @everyone"), "\\[x\\]\\(url\\) \\@everyone");
        assert!(!helper_core::shop_role_permissions_safe(
            Permissions::ADMINISTRATOR.bits()
        ));
        assert!(helper_core::shop_role_permissions_safe(
            Permissions::VIEW_CHANNEL.bits()
        ));
    }
}
