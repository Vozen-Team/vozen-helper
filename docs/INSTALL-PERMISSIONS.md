# Helper installation permissions

The official `/api/install/start` flow requests `19099133930742`, the union of
the Discord permissions used by the current 47-feature catalogue, conditional
runtime actions and dashboard resource creation. Public site and panel install
buttons already use this shared flow.
The Discord application's server-install defaults use the same mask with the
`bot` and `applications.commands` scopes; these defaults are checked separately
when publishing because they are stored by Discord, not in this repository.

| Feature/action | Requested permissions (Discord bit positions) |
| --- | --- |
| Messages, cards, announcements and history | View Channel (10), Send Messages (11), Embed Links (14), Attach Files (15), Read Message History (16) |
| Reactions and configured external custom emojis | Add Reactions (6), Use External Emojis (18) |
| Invites, server protection and audit activity | Manage Server (5), View Audit Log (7) |
| Moderation actions | Kick Members (1), Ban Members (2), Manage Messages (13), Moderate Members (40) |
| Staff alerts using a non-mentionable role | Mention Everyone (17) |
| Roles, rewards, verification, shop delivery and nickname settings | Manage Roles (28), Change Nickname (26), Manage Nicknames (27) |
| Channel/category creation and temporary voice rooms | Manage Channels (4), Connect (20), Move Members (24) |
| Tickets, threads and protected read-only channels | Manage Threads (34), Create Public Threads (35), Create Private Threads (36), Send Messages in Threads (38) |
| Native scheduled events | Manage Events (33), Create Events (44) |
| Emoji inventory adapter and application-command requirements | Manage Guild Expressions (30), Use Application Commands (31) |

The adapter preflight currently requires Manage Guild Expressions for the emoji
inventory. Native events use Create Events as well as the Manage Events adapter
requirement. Protected channel creation needs the thread flags because it writes
explicit thread permission overwrites, even when no thread is being created.

The invite does not request Administrator, voice playback, webhook management,
native polls or other permissions without a current implementation requirement.
The permissions catalogue and resource-creation tests check the mask against the
mapped adapter dependencies and all six dashboard creation paths. The OAuth test
also checks the complete 28-flag set and preserves the callback, PKCE and scopes.

## Existing installations and limits

Existing servers must open the official invite again, select the same server
and approve the updated permissions. Changing the invite does not change the
bot's existing role automatically. No removal of the bot or stored data is needed.

Feature activation, user authorization and Discord preflight checks remain in
place. Channel overwrites and role hierarchy can still block an operation: the
Helper role must be above the roles or members it manages. Disabled or blocked
features remain disabled or blocked.

Gateway intents are separate from this permission mask. `GUILD_MEMBERS` and
`MESSAGE_CONTENT` still need the application's existing gateway/portal setup;
an OAuth permission bitfield cannot enable privileged intents.

References: [Discord permissions](https://docs.discord.com/developers/topics/permissions)
and [Discord OAuth2](https://docs.discord.com/developers/topics/oauth2).
