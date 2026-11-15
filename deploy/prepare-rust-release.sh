#!/usr/bin/env bash
set -euo pipefail
# Secrets (.env, data) are written below: keep everything owner-only by default.
umask 077

version="${1:?release version required}"
root=/home/vozen/vozen-helper-rust
node_root=/home/vozen/vozen-helper
release="$root/releases/$version"

# A release starts from the legacy Node environment, but the owner-only tracker
# identity belongs to the Rust service. Preserve it from the active Rust env so
# a routine deploy cannot silently disable the private administration panel.
read_existing_env_value() {
  local key="$1"
  local source value
  for source in "$root/shared/.env" "$node_root/.env"; do
    [[ -f "$source" ]] || continue
    value="$(awk -F= -v key="$key" '$1 == key { sub(/^[^=]*=/, ""); found=$0 } END { print found }' "$source")"
    if [[ -n "$value" ]]; then
      printf '%s' "$value"
      return 0
    fi
  done
}

oauth_secret="${DISCORD_OAUTH_CLIENT_SECRET:?set DISCORD_OAUTH_CLIENT_SECRET to the real Discord application secret}"
vozen_oauth_client_id="${VOZEN_ECOSYSTEM_OAUTH_CLIENT_ID:-1537738930722443364}"
private_tracker_client_id="${HELPER_PRIVATE_TRACKER_CLIENT_ID:-$(read_existing_env_value HELPER_PRIVATE_TRACKER_CLIENT_ID)}"
private_tracker_owner_id="${HELPER_PRIVATE_TRACKER_OWNER_ID:-$(read_existing_env_value HELPER_PRIVATE_TRACKER_OWNER_ID)}"
topgg_token="${HELPER_TOPGG_TOKEN:-$(read_existing_env_value HELPER_TOPGG_TOKEN)}"
entitlement_url="${VOZEN_ENTITLEMENT_URL:-$(read_existing_env_value VOZEN_ENTITLEMENT_URL)}"
entitlement_secret="${VOZEN_ENTITLEMENT_SECRET:-$(read_existing_env_value VOZEN_ENTITLEMENT_SECRET)}"

mkdir -p "$release" "$root/shared/data"
tar -xzf /home/vozen/helper-release.tgz -C "$release"
cp "$node_root/.env" "$root/shared/.env"

sed -i \
  -e '/^DISCORD_APPLICATION_ID=/d' \
  -e '/^DISCORD_OAUTH_CLIENT_ID=/d' \
  -e '/^DISCORD_OAUTH_CLIENT_SECRET=/d' \
  -e '/^DISCORD_OAUTH_REDIRECT_URI=/d' \
  -e '/^HELPER_OAUTH_SUCCESS_REDIRECT=/d' \
  -e '/^VOZEN_ECOSYSTEM_OAUTH_CLIENT_ID=/d' \
  -e '/^VOZEN_OAUTH_CLIENT_ID=/d' \
  -e '/^HELPER_PRIVATE_TRACKER_CLIENT_ID=/d' \
  -e '/^HELPER_PRIVATE_TRACKER_OWNER_ID=/d' \
  -e '/^HELPER_DATABASE_URL=/d' \
  -e '/^HELPER_PRODUCT_ROOT=/d' \
  -e '/^HELPER_BIND_ADDR=/d' \
  -e '/^HELPER_SESSION_SECRET=/d' \
  -e '/^HELPER_TOPGG_TOKEN=/d' \
  -e '/^HELPER_ALLOWED_ORIGIN=/d' \
  -e '/^HELPER_API_ONLY=/d' \
  -e '/^HELPER_ALLOW_LEGACY_SESSION=/d' \
  -e '/^VOZEN_ENTITLEMENT_URL=/d' \
  -e '/^VOZEN_ENTITLEMENT_SECRET=/d' \
  "$root/shared/.env"

client_id="$(awk -F= '/^CLIENT_ID=/{print $2}' "$node_root/.env")"
printf '\nDISCORD_APPLICATION_ID=%s\n' "$client_id" >> "$root/shared/.env"
printf 'DISCORD_OAUTH_CLIENT_ID=%s\n' "$client_id" >> "$root/shared/.env"
printf 'DISCORD_OAUTH_CLIENT_SECRET=%s\n' "$oauth_secret" >> "$root/shared/.env"
printf 'DISCORD_OAUTH_REDIRECT_URI=https://api.vozen.org/rust/api/oauth/callback\n' >> "$root/shared/.env"
printf 'HELPER_OAUTH_SUCCESS_REDIRECT=https://vozen.org/panel/helper-tracker/\n' >> "$root/shared/.env"
printf 'VOZEN_ECOSYSTEM_OAUTH_CLIENT_ID=%s\n' "$vozen_oauth_client_id" >> "$root/shared/.env"
printf 'HELPER_DATABASE_URL=%s/vozen-helper.db\n' "$node_root" >> "$root/shared/.env"
printf 'HELPER_PRODUCT_ROOT=%s/current\n' "$root" >> "$root/shared/.env"
printf 'HELPER_BIND_ADDR=127.0.0.1:8788\n' >> "$root/shared/.env"
printf 'HELPER_SESSION_SECRET=%s\n' "$(openssl rand -hex 32)" >> "$root/shared/.env"
printf 'HELPER_ALLOWED_ORIGIN=https://vozen.org\nHELPER_API_ONLY=false\nHELPER_ALLOW_LEGACY_SESSION=false\n' >> "$root/shared/.env"
if [[ -n "$private_tracker_client_id" || -n "$private_tracker_owner_id" ]]; then
  : "${private_tracker_client_id:?set HELPER_PRIVATE_TRACKER_CLIENT_ID and HELPER_PRIVATE_TRACKER_OWNER_ID together}"
  : "${private_tracker_owner_id:?set HELPER_PRIVATE_TRACKER_CLIENT_ID and HELPER_PRIVATE_TRACKER_OWNER_ID together}"
  printf 'HELPER_PRIVATE_TRACKER_CLIENT_ID=%s\n' "$private_tracker_client_id" >> "$root/shared/.env"
  printf 'HELPER_PRIVATE_TRACKER_OWNER_ID=%s\n' "$private_tracker_owner_id" >> "$root/shared/.env"
fi
if [[ -n "$topgg_token" ]]; then
  printf 'HELPER_TOPGG_TOKEN=%s\n' "$topgg_token" >> "$root/shared/.env"
fi
if [[ -n "$entitlement_url" || -n "$entitlement_secret" ]]; then
  : "${entitlement_url:?set VOZEN_ENTITLEMENT_URL and VOZEN_ENTITLEMENT_SECRET together}"
  : "${entitlement_secret:?set VOZEN_ENTITLEMENT_URL and VOZEN_ENTITLEMENT_SECRET together}"
  printf 'VOZEN_ENTITLEMENT_URL=%s\nVOZEN_ENTITLEMENT_SECRET=%s\n' "$entitlement_url" "$entitlement_secret" >> "$root/shared/.env"
fi
chmod 600 "$root/shared/.env"
chmod 755 "$release/bin/vozen-helper"
ln -sfn "$release" "$root/current"

stat -c '%n %s bytes' "$release/bin/vozen-helper"
