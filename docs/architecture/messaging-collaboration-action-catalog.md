# messaging / collaboration action catalog

This note fixes the first shared messaging / collaboration taxonomy for Slack- and Discord-style providers.

It is intentionally a **taxonomy-only** document. It does not claim that a live Slack or Discord interceptor, bot mediation path, or product-grade approval runtime already exists.

## Why this note exists

P11-1 fixed the ownership boundary between:

- provider-specific taxonomy
- generic REST / OAuth lineage
- messaging / collaboration taxonomy
- messaging / collaboration contract
- policy and record reflection

Before `agenta-core` gets concrete messaging contract types, the repository still needs one stable answer to two questions:

1. which shared collaboration action families survive above the generic REST seam?
2. which minimum Slack / Discord provider actions should the PoC treat as the first representative candidates for those families?

This note fixes both so later implementation work can add code and policy against a stable taxonomy instead of re-deciding action families and provider mappings mid-flight.

## Fixed shared action families

The checked-in shared collaboration taxonomy now fixes these four provider-neutral action families:

- `message.send`
- `channel.invite`
- `permission.update`
- `file.upload`

These are intentionally **higher level** than REST descriptors such as `POST /channels/{id}/messages` and intentionally **lower level** than future control-plane UX concepts such as reviewer workflows or policy bundles.

### What each family means

#### `message.send`

Use when the primary collaboration intent is delivering message content into a channel, thread, or conversation.

Carries redaction-safe hints such as:

- provider lineage
- target hint
- channel or conversation hint
- delivery scope
- attachment-count hint when available

Does **not** carry:

- message body text
- rich text blocks or embeds
- thread history
- recipient rosters

#### `channel.invite`

Use when the primary collaboration intent is expanding participation in a channel-like surface such as a Slack channel or Discord thread.

Carries redaction-safe hints such as:

- channel or conversation hint
- membership target kind
- delivery scope

Does **not** carry:

- invite URLs
- full participant lists
- raw invitation metadata that would leak private membership state

#### `permission.update`

Use when the primary collaboration intent is changing a permission or access-control overwrite on a collaboration surface.

Carries redaction-safe hints such as:

- permission target kind
- target hint
- channel or conversation hint when available

Does **not** carry:

- raw ACL payloads
- full permission matrices
- provider-native opaque security objects

#### `file.upload`

Use when the primary collaboration intent is publishing a file or attachment into a collaboration surface.

Carries redaction-safe hints such as:

- file target kind
- channel or conversation hint
- attachment-count hint

Does **not** carry:

- file bytes
- preview URLs
- OCR or extracted content

## Fixed minimal provider candidates

The first shared taxonomy is intentionally small. It proves the common action families against a narrow but representative Slack / Discord sample.

| Provider | Provider action key | Common family | Surface | Delivery / target hints fixed for the PoC | Why it belongs here |
| --- | --- | --- | --- | --- | --- |
| Slack | `chat.post_message` | `message.send` | `slack.chat` | `channel_hint`, `delivery_scope=public_channel` | message delivery is the primary collaboration intent |
| Slack | `conversations.invite` | `channel.invite` | `slack.conversations` | `channel_hint`, `membership_target_kind=channel_member`, `delivery_scope=public_channel` | adding members is more important than the lower-level REST method |
| Slack | `files.upload_v2` | `file.upload` | `slack.files` | `channel_hint`, `file_target_kind=channel_attachment`, `attachment_count_hint` | file publication is the primary intent |
| Discord | `channels.messages.create` | `message.send` | `discord.channels` | `channel_hint`, `delivery_scope=public_channel` | channel message creation is still a collaboration send action |
| Discord | `channels.thread_members.put` | `channel.invite` | `discord.threads` | `conversation_hint`, `membership_target_kind=thread_member`, `delivery_scope=thread` | thread member add is a collaboration participation expansion |
| Discord | `channels.permissions.put` | `permission.update` | `discord.permissions` | `channel_hint`, `permission_target_kind=channel_permission_overwrite` | permission overwrite mutation is the collaboration intent |

## Why this first set is enough

This first candidate set proves that the messaging taxonomy can model:

- outbound message delivery across Slack and Discord
- membership expansion on both channel-like and thread-like surfaces
- a collaboration permission mutation shape
- a file publication shape without carrying file contents

That is enough to stabilize the shared action-family names and the first redaction-safe target hints without needing to solve every messaging edge case in one phase.

## Fixed redaction posture for the catalog

All candidates in this note follow the same messaging redaction rule:

- keep action family, provider lineage, target hints, channel / conversation hints, membership / permission / file target kinds, delivery scope, attachment-count hints, and docs-backed auth / risk descriptors
- drop raw message bodies, uploaded bytes, preview URLs, invite links, participant rosters, and opaque provider payloads

## Deliberate non-goals for this catalog

Still out of scope here:

- complete Slack and Discord endpoint coverage
- webhook sends or incoming-webhook-specific action naming
- ephemeral-message, reaction, thread-archive, or moderation-specific action families
- content inspection, DLP, malware scanning, or file-type classification
- runtime proof that a Slack or Discord token actually carried the documented permissions
- live provider mediation, fail-closed claims, or inline approval pauses
- control-plane reviewer UX, notification fanout, or approval reconciliation

The point of this note is smaller: later phases should be able to build on a stable shared messaging taxonomy and a stable first candidate set.

## Checked-in code mirror

The current repository mirrors this catalog in:

- `cmd/agent-auditor-hostd/src/poc/messaging/contract.rs`
- `cmd/agent-auditor-hostd/src/poc/messaging/taxonomy.rs`

The PoC candidate set is represented by:

- `MessagingActionKind`
- `MessagingActionFamily`
- `MessagingProviderActionCandidate`
- `TaxonomyPlan::preview_candidates()`

## Related docs

- phase boundary: [`messaging-collaboration-governance-foundation.md`](messaging-collaboration-governance-foundation.md)
- generic REST boundary below this layer: [`generic-rest-oauth-governance-foundation.md`](generic-rest-oauth-governance-foundation.md)
- architecture overview: [`overview.md`](overview.md)
- provider abstraction boundary: [`provider-abstraction-foundation.md`](provider-abstraction-foundation.md)
