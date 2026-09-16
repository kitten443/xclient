# ADR-0008 — Subscription header safety

- **Status:** Accepted
- **Date:** 2026-09-16
- **Deciders:** MyVpn maintainers
- **Supersedes:** —
- **Superseded by:** —
- **Implementation status:** Implemented in `MyVpn.Core/Subscriptions/`
  (catalog, registry, parsers, bounded header bag, URL safety, user-info parser).
  The transport that consumes `encrypt-tag`, the consent UI, and the body-comment
  channel are planned.

## Context

A subscription response is **attacker-influenced input**. The provider — or
anyone who can compromise the provider, or terminate TLS in front of it —
controls every response header. Several providers (Happ, Marzban, NeXT-Panel and
others) documented a header vocabulary that can, in the worst case, replace a
client's routing rules, supply a raw core configuration, change DNS, register
credentials, redirect the subscription to another host, or trigger outbound
telemetry carrying a hardware identifier.

`docs/research/05-happ-subscription-headers.md` catalogued the documented
vocabulary from the public developer documentation (§1.3, 77 parameters of which
61 are documented as deliverable via HTTP header) and reconstructed grammars
where Happ documents by example rather than by specification (§1.4). Its central
security answer is unambiguous: **no header may change routing, TUN, DNS or
credentials automatically — zero exceptions.**

The naive designs fail in specific, documented ways:

* Folding an empty toggle value to "off" lets a provider reset a user setting by
  sending an empty header. Happ's documented semantics are
  *presence-with-exception*: `true`/`1` enables, **any other non-empty value**
  disables, and an **empty** value means *unspecified*.
* Letting a provider's `new-url`/`fallback-url` be contacted automatically turns
  a metadata field into an outbound request, an SSRF pivot and a subscription
  hijack.
* Applying `custom-tunnel-config` — Happ documents it as *"pass your own tunnel
  configuration for the sing-box core"* — hands a remote server arbitrary core
  configuration.
* A generic "map any header to a setting" convenience makes every future header a
  configuration channel by default.
* Header-injection (`\r`, `\n`, C0) reaching a `User-Agent`, a log line or a
  config file is a classic response-splitting primitive.

## Decision

### The three gates

Every recognised header is declared in a single data table
(`HeaderCatalog.All` in `MyVpn.Core/Subscriptions/SubscriptionHeaderRegistry.cs`)
with one **gate** that the registry enforces. The gate is a property of the
header, checked by the registry against the catalog — **not** a convention
individual parsers are trusted to follow. Currently **65 headers**: 12 `Auto`,
48 `RequiresConfirmation`, 5 `Refused`.

**`Auto` — applied automatically; display and metadata only.** Restricted to
values that cannot change where traffic flows and cannot leak a credential.
The 12 implemented: `announce`, `content-disposition`, `profile-title`,
`profile-update-interval`, `profile-web-page-url`, `sub-info-button-link`,
`sub-info-button-text`, `sub-info-color`, `sub-info-text`,
`subscription-request-timeout`, `subscription-userinfo`, `support-url`.

Two of these deserve an explicit rule:

* `support-url` and `profile-web-page-url` are **rendered, never fetched**.
* `sub-info-button-link` is `Auto` only in the sense of *being displayed as a
  button*; it is **never auto-opened**, and its value is only used if
  `UrlSafety.IsSafeHttpUrl(...)` accepts it. There is no code path that opens a
  provider-supplied link or deeplink without a user click.

**`RequiresConfirmation` — parsed into a typed `PendingChange`, never applied.**
The 48 implemented: `app-auto-start`, `block-bind-to-tunnel-enable`,
`change-user-agent`, `check-url-via-proxy`, `color-profile`,
`dns-from-json-enable`, `exclude-apns-enable`, `exclude-local-networks-enable`,
`exclude-routes`, `exclude-routes-set`, `fallback-url`, `hide-settings`,
`http-auth-mode`, `http-auth-password`, `http-auth-user`, `inbound-http-enable`,
`include-all-networks-enable`, `mux-enable`, `mux-quic`, `mux-tcp-connections`,
`mux-xudp-connections`, `new-domain`, `new-url`, `no-limit-enabled`,
`no-limit-xhttp-enabled`, `per-app-proxy-list`, `per-app-proxy-list-invert`,
`per-app-proxy-list-set`, `per-app-proxy-mode`, `proxy-enable`,
`proxy-ping-timeout`, `routing-enable`, `sniffing-enable`, `socks-auth-mode`,
`socks-auth-password`, `socks-auth-user`, `subscription-auto-update-enable`,
`subscription-auto-update-open-enable`, `subscription-autoconnect`,
`subscription-pin`, `subscriptions-collapse`, `subscriptions-sort-type`,
`tun-enable`, `tun-mode`, `tun-type`, `user-agent-geo-files`,
`xray-tun-enable`, `xray-tun-mtu`.

A `PendingChange` binds consent to the exact `(subscription, header, value)`
triple through a SHA-256 `ValueFingerprint` and a `ConsentToken`. Without that
binding a provider could present a harmless request, obtain a one-click
confirmation, and then change the value on the next refresh while the client
kept applying the stored "yes".

**`Refused` — recognised, reported, never applied and never offered for
one-click acceptance.** The 5 implemented: `custom-tunnel-config`, `providerid`,
`routing`, `subscription-always-hwid-enable`,
`subscription-alternative-hwid-enabled`. `RefusedHeaderParser` emits a
`Warning`-severity `MyVpnError` (`error.header.refused_for_security`) naming
exactly which headers were sent, and produces **no** `PendingChange`.

`custom-tunnel-config` being `Refused` rather than
`RequiresConfirmation` is deliberate: it is arbitrary core configuration from a
remote server. Promoting it to a consent prompt would require a complete schema
allow-list first, and a diff-style review of a JSON blob is not meaningful
consent.

### The rule

**No header may influence routing, TUN, DNS or credentials automatically — zero
exceptions.** Structurally, Gate B and Gate C values never enter applied
settings: `RequiresConfirmation` values leave the parser as `PendingChange`
records, `Refused` values leave as a `RefusedHeaders` list, and only
`SubscriptionMetadata` (the `Auto` surface) is applied without user action. The
registry re-validates every emitted `PendingChange` against the catalog gate, so
a buggy parser cannot smuggle a Gate-B change into the auto-applied metadata.

### Toggle semantics

The implemented `HeaderValueParsing.Evaluate` is three-state, matching the
documented presence-with-exception rule:

| Received value | `ToggleState` |
|---|---|
| absent, or empty | `Unspecified` — the setting is left untouched |
| `true` (case-insensitive) or `1` | `On` |
| any other non-empty value | `Off` |

**An empty toggle value is never folded to `Off`.** Folding it would let a
provider disable a user's protection by sending nothing.

### Duplicate policy

`RawHeaderBag.GetSingle(name)` returns `null` when a header appears more than
once, because arbitrarily choosing one is exactly the "last wins" behaviour that
lets a provider override an earlier security-relevant value. Parsers that must
handle duplicates call `GetValues` and apply a declared `DuplicatePolicy`:

* `Unanimous` (default) — all values must be identical, otherwise the header is
  rejected;
* `JoinList` — values are combined in order, then validated as a list;
* `RejectOnConflict` — any disagreement rejects the header outright, used for
  security-relevant scalars (for example `subscription-userinfo`, where merging
  traffic counters would be wrong under any reading).

### Bounded capture, control-character rejection, fingerprints

`RawHeaderBag.FromPairs` is the only place raw headers enter the application and
applies every bound **before** any trust decision:

* `MaxHeaderCount` 128, `MaxNameLength` 128, `MaxValueLength` 8192,
  `MaxTotalBytes` 65 536;
* RFC 9110 field-name token validation (`IsValidToken`);
* **rejection of every C0 control character and `0x7F`** — `\r`, `\n`, `\0`,
  VT, FF — recorded in `Rejected` with a machine-readable reason, which is what
  prevents header-injection reaching a `User-Agent`, a log line or a config file;
* unknown headers are **preserved but inert**: retained as opaque strings with a
  SHA-256 fingerprint, never interpreted as configuration, which gives forward
  compatibility without giving a provider a control channel.

Nothing is silently dropped: every rejected header is recorded with a
`ReasonCode` and a `ReasonKey` so diagnostics can explain why a provider's title
or quota did not appear. Header names are matched case-insensitively
(`StringComparer.OrdinalIgnoreCase`, per RFC 9110); enum values are normalised
case-insensitively; every other value (titles, user agents, base64 payloads,
URLs, passwords) is case-sensitive and preserved verbatim.

### URL safety

`UrlSafety` refuses, by default and at parse time: non-HTTP(S) schemes, plain
`http` when the subscription did not opt in (`https`-only by default), URLs with
embedded credentials (`user:pass@`), and any address in loopback, RFC 1918,
link-local, CGNAT (`100.64.0.0/10`), benchmarking, documentation, multicast, or
unspecified ranges — plus the always-local host names (`localhost`,
`metadata.google.internal`, `instance-data`). The subscription endpoint itself
is the one exception: a subscription hosted on a private address is permitted
because refusing it would break legitimate self-hosted panels, but a *header*
supplied URL pointing there is refused.

The check is applied **twice** where it matters: textually at parse time and
again to the resolved `IPAddress` before the HTTP layer connects
(`UrlSafety.IsAddressAllowed`), because a textual check cannot see a public
hostname that resolves to a private address (DNS rebinding). This limitation is
documented in the code rather than hidden.

### There is no device-limit header

Happ implements device limiting through a URL `installid` plus an external
`check.happ-proxy.com` service, and through local HWID comparison. **Neither is a
response header.** MyVpn does **not** invent a `device-limit` header, does **not**
implement `providerid`'s documented daily outbound call carrying a domain hash,
HWID and OS version, and exposes no HWID/telemetry header as a setting. If a
future opt-in telemetry feature is ever considered, it is off by default with an
explicit description, and it is a separate ADR.

### Secrets

`socks-auth-password` and `http-auth-password` are credentials: they are bounded,
never logged, redacted in diagnostics, and stored with the same protection as
other credentials. They are `RequiresConfirmation`, never `Auto`.

## Consequences

**Positive**

* A malicious or compromised provider cannot change routing, TUN, DNS or
  credentials, and cannot cause network egress, without an explicit,
  value-bound user action.
* The entire set of things a provider can influence is one reviewable table with
  one visible gate per row.
* An unknown header is inert by construction rather than by accident.
* Header-injection, SSRF, duplicate smuggling and toggle-reset are all closed by
  mechanisms that exist today, not by policy statements.

**Negative / costs**

* A provider that legitimately wants to push a setting can only propose it; this
  is a deliberate product cost.
* The confirmation UI (planned) must render a meaningful diff, including
  destructive semantics: `exclude-routes-set` is documented by Happ as
  *clearing the existing list first*.
* Gate assignments are a maintenance burden: adding a header requires choosing a
  gate, and the default must be the safe one. The registry's catalog build fails
  loudly on a duplicate name, and a test should assert that every `Auto` entry is
  display-only.

**Known gap**

* The `Happ`-documented `encrypt-tag` header (Base64 AES-128-GCM tag; body
  ciphertext; key selected by the URL's `?key=`) is **transport-critical** and
  belongs *below* this registry: a malformed tag must reject the whole response
  before anything is parsed. It is not implemented yet, and it is deliberately
  absent from the catalog so it cannot be treated as metadata.
* The `#name: value` body-comment channel documented by Happ is not implemented;
  when it is, it must reuse the same parsers, the same limits and the same gates,
  and a header/body disagreement must be rejected rather than merged.

## Alternatives considered

* **Two gates (apply / don't apply), with a warning for the rest.** Rejected: it
  cannot represent "show the user, but require a bound confirmation", which is
  the correct handling for a routing change, and it makes a one-click "allow
  provider settings" toggle the only consent model.
* **Trust `custom-tunnel-config` behind a confirmation prompt.** Rejected:
  arbitrary core configuration is not something a user can meaningfully
  adjudicate; it is `Refused` unless a complete schema allow-list is built.
* **Auto-apply routing/TUN headers because "the provider is the source of the
  subscription and the user chose them".** Rejected: the provider is not the
  user, the endpoint is attacker-influenceable in transit, and a subscription is
  chosen for its servers, not as a grant of configuration authority.
* **Fold empty toggles to `Off` (a plain boolean parse).** Rejected: it lets a
  provider reset user settings by omission.
* **"Last wins" for duplicated headers.** Rejected: it is a smuggling primitive.
* **A generic header→setting mapper for unknown headers.** Rejected: it makes
  every future header a configuration channel and is the single most likely way
  the Gate-C guarantee would be lost.
* **Fetch `fallback-url` automatically (as Happ documents) or auto-open
  `sub-info-button-link`.** Rejected: a metadata field must not cause network
  egress or launch a deeplink.
* **`file://`/`javascript:`/`data:`/custom-scheme URLs.** Rejected outright, and
  `UrlSafety` refuses anything that is not `http`/`https`.
* **Textual-only URL validation.** Rejected as insufficient: DNS rebinding is
  real, so the address predicate is also applied post-resolution.

## References

* `docs/research/05-happ-subscription-headers.md` — **primary grounding**: §1.2
  delivery model and the documented toggle rule, §1.3 the master header
  inventory with gates, §1.4 per-header grammar (including
  `subscription-userinfo`, the 25/200-character caps, the enum and integer
  ranges, and the `exclude-routes-set` clearing rule), §1.5 spec-vs-convention
  separation, §1.6 gaps and things not to invent (including "no device-limit
  header"), §2.5 the three gates, §3.2 normative anti-abuse rules A1–A12,
  §3.3 the risk register, §7 licensing.
* `docs/research/01-v2rayn-architecture.md` §1.6 and §1.10 — the prior-art
  subscription pipeline and the failure modes to avoid.
* Implemented code: `src/MyVpn.Core/Subscriptions/SubscriptionHeaderRegistry.cs`
  (`HeaderCatalog`, `SubscriptionHeaderRegistry`, `ToggleState`,
  `HeaderValueParsing`), `src/MyVpn.Core/Subscriptions/HeaderParsing.cs`
  (`HeaderApplyGate`, `DuplicatePolicy`, `HeaderDescriptor`, `PendingChange`,
  `ParseResult`), `src/MyVpn.Core/Subscriptions/RawHeaderBag.cs`
  (`HeaderLimits`, control-character and token validation, SHA-256 fingerprint),
  `src/MyVpn.Core/Subscriptions/SubscriptionHeaderParsers.cs`
  (`RefusedHeaderParser`, `ConfirmationGatedParser`),
  `src/MyVpn.Core/Subscriptions/SubscriptionUserInfo.cs`,
  `src/MyVpn.Core/Net/UrlSafety.cs`,
  `src/MyVpn.Core/Results/ErrorCodes.cs` (`subscription.*`).
* Public provider documentation: Happ developer docs
  <https://www.happ.su/main/dev-docs> (app-management, provider-id, routing,
  encrypting-subscription-content, limited-links, hwid-links, emoji) — treated as
  documentation only; no Happ code was read or copied (ADR-0009).
* De-facto conventions documented by third parties (Clash/Stash/NeXT-Panel/
  Marzban subscription docs), reimplemented from documentation.
* ADR-0009 (licensing and provenance), ADR-0011 (transport/NAT strategy).
