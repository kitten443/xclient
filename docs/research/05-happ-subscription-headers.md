# 05 — Happ-Compatible Subscription Headers: Research & Design

| Field | Value |
|---|---|
| Status | Research complete; implementation not started |
| Scope | HTTP response headers delivered with a subscription download, as documented publicly by Happ, plus the de-facto cross-panel conventions |
| Target | MyVpn (.NET 8), cross-platform Xray client |
| Author | Happ-Compatible Subscription Header Research Agent |
| Primary source | <https://www.happ.su/main/dev-docs> (public documentation only) |

> **Licensing/derivation statement (see §7):** everything below is derived from *public documentation*. No proprietary or closed-source client code (Happ or any third party) was read, copied, decompiled, or transcribed. Code sketches in §2 are original design artifacts. The de-facto header names are public conventions documented by several open projects; they are re-implemented from their documentation, not from their source.

---

## 1. Findings

### 1.1 Retrieval log

The Happ docs site is a GitBook. The rendered HTML is JS-heavy and truncates, but GitBook exposes parallel Markdown and an index, which is what this research used. All findings below are from the **Markdown mirror** (`<page>.md`), which is byte-equivalent to the rendered page.

| # | URL | Result |
|---|---|---|
| 1 | <https://www.happ.su/main/dev-docs> | Retrieved (index) |
| 2 | <https://www.happ.su/main/dev-docs.md> | Retrieved (Markdown index) |
| 3 | <https://www.happ.su/main/llms.txt> | Retrieved (complete doc index, EN/RU/ZH) |
| 4 | <https://www.happ.su/main/sitemap.xml> | Retrieved (sitemap index) |
| 5 | <https://www.happ.su/main/sitemap-pages.xml> | Retrieved (all 31 EN page URLs) |
| 6 | <https://www.happ.su/main/dev-docs/app-management.md> | **Retrieved in full — primary header inventory** |
| 7 | <https://www.happ.su/main/ru/dev-docs/app-management.md> | Retrieved in full (cross-check) |
| 8 | <https://www.happ.su/main/dev-docs/provider-id.md> | Retrieved |
| 9 | <https://www.happ.su/main/dev-docs/routing.md> | Retrieved |
| 10 | <https://www.happ.su/main/dev-docs/encrypting-subscription-content.md> | Retrieved |
| 11 | <https://www.happ.su/main/dev-docs/limited-links.md> | Retrieved |
| 12 | <https://www.happ.su/main/dev-docs/hwid-links.md> | Retrieved |
| 13 | <https://www.happ.su/main/dev-docs/crypto-link.md> | Retrieved |
| 14 | <https://www.happ.su/main/dev-docs/emoji.md> | Retrieved |
| 15 | <https://www.happ.su/main/dev-docs/examples-of-links-and-parameters.md> | Retrieved |
| 16 | <https://www.happ.su/main/dev-docs/ping.md> | Retrieved |
| 17 | <https://www.happ.su/main/dev-docs/android-tv-api.md> | Retrieved |
| 18 | <https://www.happ.su/main/faq/adding-configuration-subscription.md> | Retrieved |
| 19 | De-facto cross-panel references | <https://marzban-docs.sm1ky.com/components/subscriptions/>, <https://stash.wiki/en/features/service-provider-subscription>, <https://nextpanel.dev/docs/systems/subscriptions> |

**Cross-check result:** the EN and RU `app-management` pages list **exactly the same 77 parameters** (diff of extracted parameter names = empty both ways). The ZH page mirrors the same standard block. There is therefore no EN-only or RU-only hidden parameter set.

**Could NOT retrieve / does not exist:**
- A formal grammar specification (ABNF/JSON Schema) for any Happ header. Happ documents by *example*, not by grammar. Grammars in §1.4 are therefore **reconstructed and marked UNVERIFIED where inferred**.
- Any GitBook JSON API asset beyond the `.md` mirror (not needed — the `.md` mirror is complete).
- Happ has **no** documented header for device limits, home-page telemetry, or a "format hint" beyond `providerid`. See §1.6.

### 1.2 Delivery model (important for the parser design)

Happ documents that *the same parameter set* can arrive through up to four channels ([app-management](https://www.happ.su/main/dev-docs/app-management)):

1. **HTTP response header** — the subject of this report. Canonical form: `name: value` on the 200 response that carries the subscription body.
2. **Subscription body comment line** — `#name: value`, one per line, above the configs.
3. **URL fragment/query** — e.g. `#?providerid=…`, `?key=…`, `#title?installid=…`.
4. **Push** (advanced announcements only; out of scope).

Consequences for MyVpn:

- A header parser registry is only *half* the story. The **same schema objects must be reusable for the `#name: value` body form**, otherwise the two channels drift.
- Precedence must be defined. Happ does not document precedence between header and body. **UNVERIFIED.** Proposed MyVpn rule (§3.2): *same-channel last-wins is forbidden; header and body are merged only when equal, otherwise the value is rejected and both raw values are surfaced as a conflict.* Safer than silently choosing.

Enable/disable semantics, quoted from [app-management](https://www.happ.su/main/dev-docs/app-management):

> "To enable a parameter, pass the value `true` or `1`; to disable it, pass any other non-empty value (for example, `0` or `false`)."

This is **not** a boolean parse. It is a *presence-with-exception* rule: `true`/`1` → enable; any other **non-empty** value → disable; **empty value → undefined**. MyVpn must model this as a three-state `ToggleDirective { Enable, Disable, Unspecified }` and must never fold "empty" into "disable".

### 1.3 Master header inventory

All 77 parameters were extracted. 61 are documented as deliverable **via HTTP header**. The table lists every header-deliverable parameter with source anchor.

Legend for **Gate** (MyVpn application gate, defined in §2.5):
`A` = auto-apply (display/metadata only) · `B` = requires explicit per-subscription user confirmation · `C` = refuse by default / never auto-execute.

| Header name (exact, as documented) | Section | Value type / domain | Gate | Source |
|---|---|---|---|---|
| `profile-update-interval` | Standard | int, hours, must be multiple of 1h | A (scheduling only) | [app-management#standard](https://www.happ.su/main/dev-docs/app-management) |
| `profile-title` | Standard | string, plain or `base64:`; **max 25 chars** | A | same |
| `subscription-userinfo` | Standard | `k=v; k=v; …` | A | same |
| `support-url` | Standard | string URL | A (display only) | same |
| `profile-web-page-url` | Standard | string URL | A (display only) | same |
| `announce` | Standard | string, plain or `base64:`; **max 200 displayed** | A | same |
| `routing-enable` | Standard | toggle (`0` disables) | **B** | same |
| `custom-tunnel-config` | Standard | JSON object | **C** | same |
| `socks-auth-mode` | Standard | `auto\|manual\|from-json\|disable` | B | same |
| `socks-auth-user` | Standard | string (secret) | B | same |
| `socks-auth-password` | Standard | string (secret) | B | same |
| `http-auth-mode` | Standard | `auto\|manual\|from-json\|disable` | B | same |
| `http-auth-user` | Standard | string (secret) | B | same |
| `http-auth-password` | Standard | string (secret) | B | same |
| `tun-type` | Standard | `singbox\|tun2proxy\|default\|xray` | **B** | same |
| `new-url` | Advanced | URL | **B** (URL rewrite) | [app-management#advanced](https://www.happ.su/main/dev-docs/app-management) |
| `new-domain` | Advanced | domain | **B** | same |
| `fallback-url` | Advanced | URL | **B** | same |
| `sub-info-color` | Advanced | `red\|blue\|green` (default blue) | A | same |
| `sub-info-text` | Advanced | string, max 200; `0` disables | A | same |
| `sub-info-button-text` | Advanced | string, max 25 | A | same |
| `sub-info-button-link` | Advanced | "any string (URL / deeplink)", *opens without validation* | **C** (auto-open) / B (show button) | same |
| `sub-expire` | Advanced | `true\|1` | A | same |
| `sub-expire-button-link` | Advanced | URL / deeplink | **C** (auto-open) / B (show) | same |
| `no-limit-enabled` | Advanced | `true\|1` | B | same |
| `no-limit-xhttp-enabled` | Advanced | `true\|1` | B | same |
| `subscription-always-hwid-enable` | Advanced | `true\|1` | **B** (privacy) | same |
| `notification-subs-expire` | Advanced | `true\|1` | A | same |
| `hide-settings` | Advanced | `true\|1` | B | same |
| `server-address-resolve-enable` | Advanced | `true\|1` | **B** | same |
| `server-address-resolve-dns-domain` | Advanced | URL (DoH) | **B** | same |
| `server-address-resolve-dns-ip` | Advanced | IP literal | **B** | same |
| `subscription-autoconnect` | App settings | `true\|1` | A | [app-management#app-settings](https://www.happ.su/main/dev-docs/app-management) |
| `subscription-autoconnect-type` | App settings | `lastused\|lowestdelay\|random` | A | same |
| `subscription-ping-onopen-enabled` | App settings | `true\|1` | A | same |
| `subscription-auto-update-enable` | App settings | `true\|1` | A | same |
| `fragmentation-enable` | App settings | `true\|1` | **B** | same |
| `fragmentation-packets` | App settings | `tlshello,1-2,1-3,1-5` | **B** | same |
| `fragmentation-length` | App settings | range `50-100` | **B** | same |
| `fragmentation-interval` | App settings | range `10-20` | **B** | same |
| `fragmentation-maxsplit` | App settings | string | **B** | same |
| `noises-enable` | App settings | `true\|1` | **B** | same |
| `noises-packet-type` | App settings | `array\|str\|hex\|base64` (default array) | **B** | same |
| `noises-packet` | App settings | string, comma list | **B** | same |
| `noises-delay` | App settings | string, milliseconds | **B** | same |
| `noises-rand` | App settings | string, e.g. `1-8192` | **B** | same |
| `noises-rand-range` | App settings | string, default `0-255` | **B** | same |
| `ping-type` | App settings | `proxy\|proxy-head\|tcp\|icmp` | A | same |
| `check-url-via-proxy` | App settings | URL | B (egress) | same |
| `change-user-agent` | App settings | arbitrary string | **C** (auto-apply) / B | same |
| `app-auto-start` | App settings | string / `1` | **B** | same |
| `subscription-auto-update-open-enable` | App settings | string / `1` | A | same |
| `per-app-proxy-mode` | App settings | `off\|on\|bypass` | **B** | same |
| `per-app-proxy-list` | App settings | comma list of Android app IDs | **B** | same |
| `per-app-proxy-list-invert` | App settings | comma list of Android app IDs | **B** | same |
| `per-app-proxy-list-set` | App settings | comma list of Android app IDs | **B** | same |
| `sniffing-enable` | App settings | string / `1` | **B** | same |
| `subscriptions-collapse` | App settings | `false\|0` (inverted feature) | A | same |
| `subscriptions-expand-now` | App settings | `true\|1`; `false` ignored | A | same |
| `ping-result` | App settings | `time\|icon` | A | same |
| `mux-enable` | App settings | `true\|1` | **B** | same |
| `mux-tcp-connections` | App settings | string; doc note: min −1, max 1024 | **B** | same |
| `mux-xudp-connections` | App settings | string; min −1, max 1024 | **B** | same |
| `mux-quic` | App settings | string (e.g. `skip`) | **B** | same |
| `proxy-enable` | App settings | `true\|1` — **mutually exclusive with `tun-enable`** | **B** (TUN) | same |
| `tun-enable` | App settings | `true\|1` — **mutually exclusive with `proxy-enable`** | **B** (TUN) | same |
| `tun-mode` | App settings | `system\|gvisor` | **B** | same |
| `exclude-routes` | App settings | CIDR/IP list, spaces and commas | **B** | same |
| `exclude-routes-set` | App settings | CIDR/IP list; **clears existing list first** | **B** | same |
| `color-profile` | App settings | base64 or plain JSON; or literal `resetcolors` | A (schema-validated) | same |
| `include-all-networks-enable` | App settings | `true\|1` (iOS) | **B** | same |
| `exclude-local-networks-enable` | App settings | `true\|1` (iOS) | **B** | same |
| `exclude-apns-enable` | App settings | `true\|1` (iOS) | **B** | same |
| `dont-use-filter` | App settings | `true\|1` | A | same |
| `subscription-pin` | App settings | `true\|1` | A | same |
| `manual-block-user-agent` | App settings | `true\|1` | **B** | same |
| `subscriptions-sort-type` | App settings | `without\|ping\|alphabet` | A | same |
| `dns-from-json-enable` | App settings | `true\|1` | **B** | same |
| `user-agent-geo-files` | App settings | `safari-mac\|chrome-win\|safari-ios\|firefox-win\|chrome-android` | A | same |
| `proxy-ping-timeout` | App settings | int **5–15** s; out-of-range ignored, default 7 | A (bounded) | same |
| `hide-vpn-icon` | App settings | `true\|1` | A | same |
| `subscription-request-timeout` | App settings | int **5–15** s; default 9 | A (bounded) | same |
| `inbound-http-enable` | App settings | `true\|1` | **B** | same |
| `xray-tun-enable` | App settings | `true\|1` | **B** (TUN) | same |
| `xray-tun-mtu` | App settings | int **68–65535** | **B** (TUN) | same |
| `block-bind-to-tunnel-enable` | App settings | `true\|1` | **B** | same |
| `subscription-alternative-hwid-enabled` | App settings | `true\|1` | **B** (privacy) | same |
| `proxy-ping-mode` | App settings | `default\|double\|keepalive` | A | same |

Three further headers are documented **outside** `app-management`:

| Header | Meaning | Gate | Source |
|---|---|---|---|
| `providerid` | Provider identifier binding the subscription to a happ-proxy.com account; enables "advanced" parameters and device tracking. Delivered via header, body (`#providerid {id}`), or URL `#?providerid=`. | **C** (telemetry — see §3) | [provider-id](https://www.happ.su/main/dev-docs/provider-id) |
| `routing` | Value is a routing-profile link, e.g. `happ://routing/onadd/{base64 JSON}` or `happ://routing/add/…`, `happ://routing/off`. Installs a routing profile including remote geo-file URLs. | **C** (never auto-import) | [routing](https://www.happ.su/main/dev-docs/routing) |
| `encrypt-tag` | Base64 AES-128-GCM authentication tag; the response body is ciphertext and the URL carries `?key=<keyId>`. | **Transport-critical — handled below the metadata registry** | [encrypting-subscription-content](https://www.happ.su/main/dev-docs/encrypting-subscription-content) |

Also **present in every Happ example response but never documented as a parameter**:

| Header | Observed use | Status |
|---|---|---|
| `content-disposition: attachment; filename="213"` | Appears in every Happ HTTP example. De-facto meaning (documented by [NeXT-Panel](https://nextpanel.dev/docs/systems/subscriptions)): the `filename` is the profile name. | **UNVERIFIED** for Happ semantics |
| `content-type: application/json` | Example only; Happ subscriptions are `text/plain` lists or JSON arrays. | Incidental |

### 1.4 Per-header grammar and validation rules

Because Happ documents by example, each rule below is tagged:
**[D]** = directly documented · **[I]** = inferred from the documented example (UNVERIFIED) · **[C]** = de-facto convention documented by third-party public docs, **not** in Happ docs.

#### 1.4.1 `subscription-userinfo` — the traffic/expiry line

Source: [app-management](https://www.happ.su/main/dev-docs/app-management) ("all data is transmitted in a single header and separated by the `;` symbol"), plus de-facto [Stash](https://stash.wiki/en/features/service-provider-subscription) and [Marzban](https://marzban-docs.sm1ky.com/components/subscriptions/).

Documented example:
```
subscription-userinfo: upload=0; download=2153701362; total=0; expire=1790951622
```

Reconstructed grammar:
```
subscription-userinfo = pair *(";" [SP] pair)
pair                  = key "=" value
key                   = "upload" / "download" / "total" / "expire" / extension-key
value                 = number
number                = ["-"] 1*DIGIT ["." 1*DIGIT]
```

| Rule | Status |
|---|---|
| Separator is `;` | **[D]** |
| Keys are `upload`, `download`, `total`, `expire` | **[D]** (example) |
| All four in one header, order apparently fixed | **[I]** — do **not** rely on order; parse by key |
| `upload`/`download`/`total` are **bytes**; `expire` is a **Unix epoch second** | **[C]** (Stash/Marzban) — **UNVERIFIED in Happ docs** |
| `total=0` means **unlimited** | **[C]** — very common panel convention, **UNVERIFIED** |
| `expire=0` means **no expiry** | **[C]** — **UNVERIFIED** |
| Values may be floats (`%f`) in some panels | **[C]** (Stash shows `upload=%f; …`) — accept and round down |
| Spaces after `;` are tolerated | **[I]** — example has none, but tolerate |
| Unknown keys must be preserved, not dropped | MyVpn policy (§3) |
| Missing keys ⇒ unknown, not zero | MyVpn policy — **must not** render "0 used" for an absent `upload` |

MyVpn validation: reject negative values; clamp to `Int64` (bytes) and `Int64` (epoch) with overflow ⇒ invalid; render "used = upload + download" only when both present (Happ documents the bar as upload+download **[D]**); `total < used` ⇒ still display, flag as inconsistent.

#### 1.4.2 `profile-title`

```
profile-title = plain-title / base64-title
plain-title   = UTF8-string            ; max 25 characters
base64-title  = "base64:" base64(UTF8-string)
```
- Max length **25 characters** **[D]**.
- Plain text **or** Base64 UTF-8 **[D]**; the `base64:` sentinel is shown only for `announce` in Happ docs and for `profile-title` in [Marzban](https://marzban-docs.sm1ky.com/components/subscriptions/) **[C]**.
- Validation: decode if `base64:`; reject if decoded length > 25; strip C0/C1 controls, bidi overrides and zero-width characters before display (a title is rendered next to the profile — RTL override is a spoofing vector).

#### 1.4.3 `announce` and the `sub-info-*` family

```
announce = plain-text / "base64:" base64(UTF8-text)     ; max 200 displayed   [D]
```

Advanced announcements ([app-management](https://www.happ.su/main/dev-docs/app-management)) are a **group** with `sub-info-text` as the trigger:

| Key | Type | Required | Limits | Notes |
|---|---|---|---|---|
| `sub-info-color` | string | No | `red\|blue\|green` (default blue) | **[D]** |
| `sub-info-text` | string | **Yes\*** | max 200 chars; `0` disables; empty string disables | **[D]** |
| `sub-info-button-text` | string | No | max 25 chars | absent ⇒ no button **[D]** |
| `sub-info-button-link` | string | No | "any string (URL / deeplink)"; **"Opens in a browser, without validation"** | **[D]** — hazardous, see §3 |
| `sub-expire` | bool | No | `true\|1` | enables expiry block **[D]** |
| `sub-expire-button-link` | string | No | URL / deeplink | "Renew" button **[D]** |

Documented display logic **[D]**: expire message wins over info block; expire block shows ≤3 days before expiry or after expiry; days counted as full days, max 3.
Documented disable rule **[D]**: "To disable an announcement activated via an HTTP header or push, send the value 0." ⇒ `sub-info-text: 0` is a **sentinel**, not text.

#### 1.4.4 Toggles

`X: true` or `X: 1` ⇒ enable. Any other **non-empty** value ⇒ disable. Empty ⇒ unspecified. **[D]**
`subscriptions-expand-now` — `false` is **ignored** (only expands, cannot collapse) **[D]**.
`subscriptions-collapse` — documented value to *disable collapsing* is `false`/`0`; i.e. the header name is inverted relative to its example **[D]** — implement exactly as documented and do not "fix" it.

#### 1.4.5 Enumerations (validate against the closed set, normalize case)

| Header | Allowed |
|---|---|
| `tun-type` | `singbox`, `tun2proxy`, `default`, `xray` |
| `tun-mode` | `system`, `gvisor` |
| `socks-auth-mode`, `http-auth-mode` | `auto`, `manual`, `from-json`, `disable` |
| `per-app-proxy-mode` | `off`, `on`, `bypass` |
| `ping-type` | `proxy`, `proxy-head`, `tcp`, `icmp` |
| `ping-result` | `time`, `icon` |
| `subscriptions-sort-type` | `without`, `ping`, `alphabet` |
| `subscription-autoconnect-type` | `lastused`, `lowestdelay`, `random` |
| `noises-packet-type` | `array`, `str`, `hex`, `base64` |
| `proxy-ping-mode` | `default`, `double`, `keepalive` |
| `user-agent-geo-files` | `safari-mac`, `chrome-win`, `safari-ios`, `firefox-win`, `chrome-android` |
| `sub-info-color` | `red`, `blue`, `green` |

Unknown enum value ⇒ reject the header (record issue), do **not** fall back to the first enum member.

#### 1.4.6 Bounded integers

| Header | Range | On violation |
|---|---|---|
| `profile-update-interval` | int hours, multiple of 1h **[D]**; upper bound **UNVERIFIED** | Reject; MyVpn clamps to ≥1h and ≤ configured max (propose 168h) |
| `proxy-ping-timeout` | 5–15 s **[D]** | "Values outside the range are ignored, default 7 is used" **[D]** |
| `subscription-request-timeout` | 5–15 s **[D]**; default 9 **[D]** | Clamp/reject outside range |
| `xray-tun-mtu` | 68–65535 **[D]** | Reject outside range |
| `mux-tcp-connections`, `mux-xudp-connections` | doc note: concurrency min −1, max 1024 **[D]** | Reject outside range |

#### 1.4.7 Lists

- `exclude-routes`, `exclude-routes-set`: CIDR/IP list, **"separated by spaces and commas"** **[D]**. `-set` **clears the existing list first** **[D]**. Validate each token as a literal IP or CIDR; reject hostnames; cap count and total length.
- `per-app-proxy-list`, `-invert`, `-set`: comma-separated Android application IDs **[D]**. Validate against `^[A-Za-z0-9_]+(\.[A-Za-z0-9_]+)+$`; cap count (propose 512) and each ID length (propose 255).

#### 1.4.8 JSON-valued headers (highest risk)

- `custom-tunnel-config` — "Pass your own tunnel configuration for the sing-box core", value `[json]`, Desktop only **[D]**. Happ passes it to the core. **This is arbitrary core configuration from a remote server.** MyVpn must not auto-apply it (Gate C).
- `color-profile` — base64 or plain JSON, or the literal `resetcolors` **[D]**; iOS only; documented field set is a fixed palette of colors, array lengths, one float and two enum-ish strings (`buttonImageType`, `backgroundImageType`). Schema-validate field-by-field; drop unknown fields silently.

Both must be parsed with a **bounded, non-executing** JSON reader (see §2.9), mapped to typed records, never bound to a live core config.

#### 1.4.9 Free-form string headers

- `change-user-agent` — arbitrary UA string **[D]**. Used by Happ to alter the UA for the *next* subscription request. **CRLF/header-injection critical** (§3.2).
- `app-auto-start`, `subscription-auto-update-open-enable`, `sniffing-enable` — documented as `[String]` but examples pass `1`. Treat as toggle.

#### 1.4.10 URL-valued headers

`support-url`, `profile-web-page-url`, `new-url`, `fallback-url`, `sub-info-button-link`, `sub-expire-button-link`, `check-url-via-proxy`, `server-address-resolve-dns-domain` (DoH). All are remote-controlled URLs. `new-url`/`new-domain` **silently rewrite the subscription address** **[D]**, and `fallback-url` is contacted automatically when the main URL fails with 300–599 or times out at 9 s **[D]**. `sub-info-button-link` is explicitly documented as opening **"without validation"** **[D]**.

#### 1.4.11 `providerid` and `encrypt-tag`

- `providerid` — opaque ID **[D]**. Presence triggers a **daily outbound GET to `https://check.happ-proxy.com/provider?id=…`** carrying domain hash, HWID, OS name and version **[D]**. That is third-party telemetry; MyVpn must not reproduce it without explicit opt-in.
- `encrypt-tag` — `Base64(AES-GCM tag)`; algorithm exactly **AES-128-GCM**, key 16 bytes, IV the literal 12-byte ASCII `kkkkkkkkkkkk`, key identified by the URL's `?key=<keyId>` parameter (the key itself is built into the client) **[D]**. The tag is **separate from the ciphertext** — "do not append the authentication tag to the ciphertext if your encryption library does this automatically" **[D]**.

This header is **not** metadata. It is needed to decrypt the body, so it must be consumed by the transport layer *before* the metadata registry runs. Validate: strict Base64, decoded length exactly 16 bytes (AES-GCM tag for 128-bit key). A malformed tag ⇒ whole response rejected, nothing parsed.

### 1.5 Spec vs convention — explicit separation

| Item | Happ-specified | De-facto convention only |
|---|---|---|
| Header `subscription-userinfo` | yes — name and `;`-format documented | units (bytes / epoch), `total=0`=unlimited, float values, case-insensitive name |
| `upload/download/total/expire` key names | yes (example) | extra keys, ordering guarantees |
| `profile-title` + 25-char cap | yes | `base64:` sentinel form |
| `profile-update-interval`, `support-url`, `profile-web-page-url` | yes | same names reused by Marzban/NeXT-Panel |
| `announce` | yes | same name reused broadly |
| `Subscription-Userinfo` / `Profile-Update-Interval` / `Profile-Web-Page-Url` **CamelCase** spellings | **no** — Happ uses lowercase | yes: Clash/Stash/NeXT-Panel emit CamelCase. HTTP names are case-insensitive, so MyVpn matches case-insensitively |
| `Content-Disposition: attachment; filename=` as profile name | not documented (only present in examples) | yes: NeXT-Panel documents it |
| Device/install limits | **no header at all** — implemented as URL `installid` + external `check.happ-proxy.com` service | — |
| TUN/routing control | yes (happ-specific) | — |

### 1.6 Gaps and things MyVpn should NOT invent

- **No documented header for device limits.** Happ's own device limiting is [Limited Links](https://www.happ.su/main/dev-docs/limited-links) (URL `installid` + SHA-256 domain hash + remote check) and [HWID Links](https://www.happ.su/main/dev-docs/hwid-links) (local HWID comparison). Neither is a response header. MyVpn must not invent a `device-limit` header.
- **No documented HTTP header for "home page URL" besides `profile-web-page-url`/`support-url`.**
- **No documented header for provider format hints** beyond `providerid` and `content-type`.
- **No documented maximum** for `profile-update-interval`, `fragmentation-maxsplit`, `noises-delay`, `noises-rand`, and several `String` types. Marked UNVERIFIED; MyVpn applies its own conservative caps.
- **No header precedence rules** between header and `#`-body delivery.
- `encrypted subscription` (`happ://crypt4/`, `happ://crypt5/`, RSA-4096 public key, `?key=` AES) is documented but is a **link/body** concern, not a response-header concern, except for `encrypt-tag`.

---

## 2. Architecture proposal

### 2.1 Design goals and invariants

| # | Invariant |
|---|---|
| I1 | **Parsers are pure.** Given a `HeaderParseContext`, a parser returns a `ParseResult` and mutates nothing outside it. |
| I2 | **Unknown headers are preserved raw and never interpreted.** They are stored as bounded byte/string blobs plus a fingerprint, never used as configuration. |
| I3 | **No arbitrary deserialization.** JSON-valued headers are read with a bounded `JsonDocument`/`Utf8JsonReader` and mapped field-by-field into sealed records. No reflection binder, no `TypeNameHandling`, no polymorphic deserialization. |
| I4 | **No execution surface.** No header value ever reaches a process argument, shell, file path, registry key, environment variable, or template. |
| I5 | **Length- and type-bounded.** Every parser declares a maximum value length; every value is type-checked and range-checked before it leaves the parser. |
| I6 | **Least privilege by gate.** Only Gate A fields may auto-apply (display/metadata). Gate B fields become typed *pending changes* that require explicit, per-subscription user confirmation. Gate C fields are refused and surfaced as a security notice. |
| I7 | **A header can never cause network egress by itself.** No auto-fetch of `new-url`/`fallback-url`, no auto-open of any link, no geo-file download, no telemetry call. |
| I8 | **Deterministic.** Registry order is total and stable (`(Priority, Id)`); identical input always yields identical output. |
| I9 | **Fail closed.** Any parser exception, budget overrun, duplicate conflict, or schema violation ⇒ that field is dropped (not defaulted), an issue is recorded, and parsing continues for other fields. |
| I10 | **Secrets never leak to logs/UI.** Credential headers are redacted in audit and diagnostics. |

### 2.2 Core types

Illustrative original design (not copied from any project):

```csharp
namespace MyVpn.Subscriptions.Headers;

/// One raw header occurrence exactly as received (framework may have split/joined).
public readonly record struct RawHeaderEntry(
    string Name,          // as received, original casing preserved for audit
    string Value,         // bounded; truncated flag separate
    int Index,            // ordinal position in the response
    bool ValueTruncated);

/// Immutable, bounded view over every header in the response.
/// This is the ONLY place unknown headers exist, and they exist as data.
public sealed class RawHeaderBag
{
    public static RawHeaderBag Capture(
        IEnumerable<KeyValuePair<string, IEnumerable<string>>> headers,
        HeaderLimits limits,
        ISubscriptionAuditSink audit);

    public IReadOnlyList<RawHeaderEntry> Entries { get; }
    public IReadOnlyList<RawHeaderEntry> GetAll(string name);   // OrdinalIgnoreCase
    public bool Contains(string name);
    public bool TryGetSingle(string name, out string value);    // false if 0 or >1 distinct
    public HeaderLimits Limits { get; }
}

/// Everything a parser may see. No app state, no service locator, no I/O.
public sealed class HeaderParseContext
{
    public required RawHeaderBag Headers { get; init; }
    public required Uri RequestUri { get; init; }        // where the sub was fetched
    public required Uri FinalUri { get; init; }          // after redirects
    public required HeaderLimits Limits { get; init; }
    public required HeaderEncoding Encoding { get; init; }
    public required ISubscriptionAuditSink Audit { get; init; }
    public CancellationToken Budget { get; init; }       // hard per-response budget
}

public enum ParseOutcome { Absent, Parsed, Ignored, Invalid, Rejected }

public sealed record ValidationIssue(
    string Code,            // stable machine code, e.g. "userinfo.negative-value"
    IssueSeverity Severity, // Info | Warning | Security
    string HeaderName,
    string Message,         // never contains the raw secret value
    string? RedactedValuePreview);

public sealed class ParseResult
{
    public required string ParserId { get; init; }
    public required int ParserVersion { get; init; }
    public required ParseOutcome Outcome { get; init; }
    public SubscriptionMetadataDelta? Delta { get; init; }  // typed, validated
    public IReadOnlyList<ValidationIssue> Issues { get; init; } = [];
    public RawHeaderEntry? Source { get; init; }

    public static ParseResult Absent(string id, int version);
    public static ParseResult Invalid(string id, int version, params ValidationIssue[] issues);
}
```

`SubscriptionMetadata` is a sealed, immutable aggregate of *typed* fields. Every field exists as `Optional<T>`-style `Maybe<T>` so "absent" and "zero/empty" are distinguishable:

```csharp
public sealed record SubscriptionMetadata
{
    // Gate A — display/metadata
    public Maybe<string>          Title { get; init; }
    public Maybe<SubscriptionUsage> Usage { get; init; }
    public Maybe<TimeSpan>        UpdateInterval { get; init; }
    public Maybe<Uri>             SupportUrl { get; init; }
    public Maybe<Uri>             WebPageUrl { get; init; }
    public Maybe<Announcement>    Announcement { get; init; }
    public Maybe<SortMode>        SortMode { get; init; }
    public Maybe<PingDisplayMode> PingDisplay { get; init; }
    public Maybe<ThemePalette>    Palette { get; init; }     // schema-validated
    public bool                   Pinned { get; init; }
    // … etc.

    // Gate B — never applied here; surfaced as pending, user-gated proposals
    public IReadOnlyList<PendingChange> PendingChanges { get; init; } = [];

    // Gate C — refused, retained only for the security notice
    public IReadOnlyList<RefusedDirective> Refused { get; init; } = [];

    // Everything unrecognized, preserved verbatim (bounded)
    public IReadOnlyList<RawHeaderEntry> UnknownHeaders { get; init; } = [];
}

public sealed record SubscriptionUsage(
    Maybe<long> UploadBytes, Maybe<long> DownloadBytes,
    Maybe<long> TotalBytes,  Maybe<DateTimeOffset> ExpiresAt,
    IReadOnlyDictionary<string,string> ExtensionPairs)
{
    public long? UsedBytes => UploadBytes.HasValue && DownloadBytes.HasValue
        ? UploadBytes.Value + DownloadBytes.Value : null;
    public bool IsUnlimited => TotalBytes is { HasValue: true, Value: 0 };
}

public sealed record PendingChange(
    string FieldId,            // stable, e.g. "tun.enable"
    string DisplaySummaryKey,  // i18n key, NOT provider-supplied text
    ChangeRisk Risk,           // Elevated | High
    object ProposedValue,      // typed, already validated
    RawHeaderEntry Source);
```

Two structural decisions worth calling out:

1. **Gate B/C values never enter `SubscriptionMetadata` as live settings.** They enter as `PendingChange`/`RefusedDirective`. This makes "parsers cannot mutate unrelated app state" a *type-level* property, not a code-review property.
2. **Unknown headers live in `SubscriptionMetadata.UnknownHeaders` and `RawHeaderBag` only.** There is no API that resolves an arbitrary header name to a setting.

### 2.3 Parser interface

```csharp
public interface ISubscriptionHeaderParser
{
    /// Stable id, namespaced: "happ.profile-title", "defacto.subscription-userinfo".
    string Id { get; }

    /// Bumped whenever the accepted grammar or validation changes.
    int Version { get; }

    /// Ordering band; lower runs first. Ties broken by Id (ordinal).
    int Priority { get; }

    /// Which application gate this parser feeds.
    HeaderGate Gate { get; }

    /// Duplicate policy for this parser's headers.
    DuplicatePolicy Duplicates { get; }

    /// Canonical (lowercase) header names this parser consumes.
    IReadOnlyCollection<string> HeaderNames { get; }

    /// Maximum accepted value length; enforced by the registry before Parse.
    int MaxValueLength { get; }

    /// Cheap check; must not allocate beyond small locals.
    bool CanParse(HeaderParseContext ctx);

    /// Pure. Must not throw; the registry still guards with try/catch + budget.
    ParseResult Parse(HeaderParseContext ctx);
}

public enum HeaderGate { DisplayMetadata = 0, BehaviorPreference = 1, SecuritySensitive = 2, TransportCritical = 3 }

public enum DuplicatePolicy
{
    /// 0 or 1 value, or N identical values -> accept. N distinct -> reject.
    Unanimous,
    /// Documented as a list: join all occurrences (bounded), then validate.
    JoinList,
    /// N distinct -> reject outright (used for security-sensitive scalars).
    RejectOnConflict,
}
```

### 2.4 Registry

```csharp
public interface ISubscriptionHeaderParserRegistry
{
    /// Total order: (Priority, Id, Version).
    IReadOnlyList<ISubscriptionHeaderParser> Parsers { get; }

    HeaderParseReport ParseAll(HeaderParseContext ctx);
    void Register(ISubscriptionHeaderParser parser);
    void Freeze();   // registration only during composition root
}

public sealed record HeaderParseReport(
    SubscriptionMetadata Metadata,
    IReadOnlyList<ParseResult> Results,
    IReadOnlyList<ValidationIssue> Issues,
    TimeSpan Elapsed);
```

Registry behaviour:

1. Sort parsers by `(Priority, Id, Version)` — total and stable.
2. For each parser: if `!CanParse` ⇒ `Absent`.
3. Guard with `try/catch` and the shared cancellation budget; an exception becomes `Outcome = Invalid` with an issue and never propagates.
4. Enforce `MaxValueLength` and the global limits **before** calling `Parse`.
5. Collect `Delta`s into the metadata builder; `PendingChange`s and `RefusedDirective`s are appended, never merged into settings.
6. Unknown-header computation: every `RawHeaderBag` entry whose name matches no parser is copied into `UnknownHeaders` (bounded, deduplicated by name, capped at N entries).

Proposed priority bands:

| Priority | Band | Examples |
|---|---|---|
| 100 | Identity/display | `profile-title`, `content-disposition` |
| 200 | Metrics | `subscription-userinfo` |
| 300 | Announcements | `announce`, `sub-info-*`, `sub-expire*` |
| 400 | Display preferences | `ping-result`, `subscriptions-sort-type`, `subscription-pin`, `sub-info-color` |
| 500 | Behavior preferences | `profile-update-interval`, `subscription-auto-update-*`, `subscription-autoconnect*` |
| 600 | Security-sensitive | `routing`, `routing-enable`, `tun-*`, `proxy-enable`, `new-url`, `new-domain`, `fallback-url`, `*auth-*`, `custom-tunnel-config` |
| 900 | Extension capture | unknown/unmatched (no parser; raw capture only) |

Note: `encrypt-tag` is **not** in the registry. It is consumed by `SubscriptionTransport` before the body is even read (§2.6).

### 2.5 Gates: what may influence routing / TUN

**Answer to the task question: no header may influence routing or TUN behaviour automatically — zero exceptions.**

| Gate | Meaning | Fields |
|---|---|---|
| **A — auto-apply** | Purely presentational or bounded scheduling. Cannot change where traffic goes. | `profile-title`, `subscription-userinfo`, `announce`, `sub-info-text/-color/-button-text`, `sub-expire`, `profile-web-page-url`*, `support-url`*, `ping-result`, `subscriptions-sort-type`, `subscription-pin`, `subscription-autoconnect*`, `subscription-ping-onopen-enabled`, `subscription-auto-update-*`, `profile-update-interval`, `dont-use-filter`, `notification-subs-expire`, `proxy-ping-*`, `user-agent-geo-files`, `subscriptions-collapse`, `subscriptions-expand-now`, `color-profile`, `server-address-resolve-*` (as *proposal* only), `proxy-ping-timeout`, `subscription-request-timeout` (bounded) |
| **B — explicit user confirmation** | Changes tunnel/routing/egress/identity. Never applied on import or refresh; presented as a diff the user accepts, per subscription, revocable. | `routing`, `routing-enable`, `custom-tunnel-config`, `tun-enable`, `proxy-enable`, `tun-type`, `tun-mode`, `xray-tun-enable`, `xray-tun-mtu`, `exclude-routes`, `exclude-routes-set`, `include-all-networks-enable`, `exclude-local-networks-enable`, `exclude-apns-enable`, `dns-from-json-enable`, `per-app-proxy-*`, `fragmentation-*`, `noises-*`, `mux-*`, `sniffing-enable`, `inbound-http-enable`, `block-bind-to-tunnel-enable`, `hide-vpn-icon`, `new-url`, `new-domain`, `fallback-url`, `change-user-agent`, `manual-block-user-agent`, `hide-settings`, `app-auto-start`, `socks-auth-*`, `http-auth-*`, `no-limit-*`, `subscription-always-hwid-enable`, `subscription-alternative-hwid-enabled`, `check-url-via-proxy`, `server-address-resolve-enable` |
| **C — refuse by default** | No safe automatic interpretation, or an explicit execution/telemetry surface. | `providerid` (third-party telemetry), `custom-tunnel-config` (arbitrary core config ⇒ Gate C by default, promotable to B only with a full schema allow-list), `sub-info-button-link` / `sub-expire-button-link` **auto-open** (show button only after scheme allow-list check), `routing` links that require downloading remote geo files |

\* `support-url` / `profile-web-page-url` are display-only: MyVpn renders the value but never fetches it and never auto-opens it.

`tun-enable` and `proxy-enable` are documented as **mutually exclusive** ("use only one of the two listed parameters" **[D]**). The registry must detect both-present and reject the pair (issue `tun.mutually-exclusive`), never "last wins".

`exclude-routes-set` **clears the existing list first** **[D]** — so a Gate-B confirmation must show the destructive semantics explicitly.

### 2.6 Parsing pipeline

```
HTTP response
  │
  ├─(1) Transport layer: enforce limits, capture RawHeaderBag
  │        • header count ≤ HeaderLimits.MaxHeaderCount
  │        • per-value length ≤ HeaderLimits.MaxValueBytes
  │        • total header bytes ≤ HeaderLimits.MaxTotalBytes
  │        • reject values containing CR, LF, NUL, C0 except HTAB
  │        • record truncation flags; never silently drop
  │
  ├─(2) Transport-critical: encrypt-tag (if ?key= present)
  │        • strict Base64, exactly 16 decoded bytes
  │        • decrypt body AES-128-GCM with IV "kkkkkkkkkkkk"
  │        • failure ⇒ reject whole response, parse nothing
  │
  ├─(3) Content sniff: text/plain list, base64 list, JSON array, HTML page
  │        • content-type is a HINT only; sniff with bounded lookahead
  │
  ├─(4) Metadata registry: ParseAll(ctx) → HeaderParseReport
  │
  ├─(5) Optional body-comment channel: "#name: value" lines
  │        • same parsers, same schemas, same limits
  │        • header/body conflicts rejected (never merged)
  │
  ├─(6) Application policy:
  │        • Gate A → apply immediately (display/metadata)
  │        • Gate B → create PendingChange list → consent UI
  │        • Gate C → RefusedDirective → security notice, audit
  │
  └─(7) Audit: parser ids+versions, issue codes, unknown-header fingerprints
```

### 2.7 Unknown header preservation

- `RawHeaderBag` keeps **every** entry, including ones no parser matched.
- `SubscriptionMetadata.UnknownHeaders` copies unmatched entries, bounded by `MaxUnknownHeaders` (propose 64) and `MaxUnknownValueBytes` (propose 1024 each, total 16 KiB).
- Each unmatched entry stores: original name, bounded value, `ValueTruncated`, and `SHA-256(name + "\0" + value)` fingerprint for audit correlation.
- Unknown values are **never** surfaced in the UI as settings, never serialized into the profile store as configuration, never passed to the core, never logged in full. Diagnostics show `name`, length, fingerprint.
- A dedicated test asserts that a service whose entire header set is unknown produces `Metadata` with zero settings and a non-empty `UnknownHeaders`.

### 2.8 Limits

| Limit | Proposed default | Rationale |
|---|---|---|
| `MaxHeaderCount` | 100 | well above observed panels |
| `MaxValueBytes` (global) | 4096 | matches Kestrel default; most values are far smaller |
| `MaxValueBytes` (`custom-tunnel-config`, `color-profile`) | 16384 | documented JSON payloads |
| `MaxTotalHeaderBytes` | 32768 | Kestrel default total |
| `MaxUnknownHeaders` | 64 | |
| `MaxUnknownValueBytes` | 1024 each / 16384 total | |
| `MaxListItems` | 512 | routing rules / app IDs |
| `MaxJsonDepth` | 16 | |
| `MaxJsonTokens` | 4096 | |
| `ParseBudget` | 250 ms per response | |
| `MaxTitleChars` | 25 | documented |
| `MaxAnnounceChars` | 200 | documented |
| `MaxSubInfoButtonChars` | 25 | documented |
| `MaxRequestTimeoutSeconds` | 5–15 | documented |
| `MaxUpdateIntervalHours` | 168 | MyVpn policy (Happ max UNVERIFIED) |

### 2.9 Safe JSON handling

For `custom-tunnel-config` and `color-profile`:

- Use `Utf8JsonReader`/`JsonDocument` with `JsonDocumentOptions { MaxDepth = 16, CommentHandling = Disallow, AllowTrailingCommas = false }`.
- Operate on a bounded `ReadOnlySequence<byte>` slice; never on an unbounded stream.
- Map **only** explicitly known fields into a sealed record. Unknown fields are ignored (not preserved into the config).
- No `JsonSerializer.Deserialize<T>` against provider-controlled types, no `JsonSerializerOptions.TypeNameHandling`, no `JsonConverter` that runs provider-supplied logic, no source-generated polymorphic dispatch.
- Reject any numeric outside the documented range; reject any string that fails the field's regex/enum.
- The typed result is stored as data. Nothing consumes it without the Gate B consent path.

### 2.10 Safe fallback

- Parser throws / exceeds budget / returns an out-of-contract result ⇒ `Outcome = Invalid`, field dropped, issue recorded, no default applied.
- Transport-level rejection (`encrypt-tag` invalid, oversize headers, CRLF) ⇒ whole response rejected; the previous good profile is retained unchanged.
- If **every** parser fails, MyVpn keeps the previous metadata and marks the refresh as "metadata unavailable" — it must not blank the UI.
- Registry is frozen after composition; a runtime parser-registration API is not exposed.

---

## 3. Risks

### 3.1 Threat model

The subscription endpoint is a **remote, unauthenticated-in-practice input controlled by the provider**. Treat every header as attacker-controlled. Relevant adversaries:

| Adversary | Capability | Goal |
|---|---|---|
| Malicious provider | full control of all headers/body | redirect traffic, exfiltrate, disable protections, spoof identity |
| Compromised provider | same, intermittent | as above, stealthy |
| Network attacker (pre-TLS or TLS-terminating middlebox) | header manipulation | as above; also CRLF/response splitting |
| Curious provider | sees client behaviour | fingerprint client from UA/link follows |

### 3.2 Anti-abuse rules (normative)

**A1 — Routing/TUN.** No header may change routing, TUN mode, DNS, excluded routes, per-app proxy lists, fragmentation, or MUX without *explicit, per-subscription, per-change user confirmation*. `custom-tunnel-config` is refused outright by default. Confirmation must be a diff-style review showing the proposed values, not a generic "allow provider settings" toggle.

**A2 — Duplicate headers.**
- Scalar + `Unanimous`: N occurrences with identical values ⇒ accept one. N distinct ⇒ reject, record `header.duplicate-conflict`. Never "first wins" or "last wins" for security-sensitive fields.
- `RejectOnConflict` (security-sensitive): any N > 1 ⇒ reject.
- `JoinList`: join all occurrences with `,`, then apply list validation and caps.
- `subscription-userinfo` with N > 1 ⇒ reject (never merge traffic numbers).
- Frameworks may fold duplicates into `a: 1, 2`; the bag must therefore also split on the documented list separators *only for list-typed parsers*, and must not split scalar parsers naively on comma.

**A3 — Case-insensitivity.** Header *names* are matched with `StringComparer.OrdinalIgnoreCase` (RFC 9110). Enum *values* are matched case-insensitively and normalized. All other values (titles, UA strings, base64, URLs, passwords) are case-sensitive and preserved verbatim where applicable.

**A4 — CRLF / header injection.** Reject any header value containing `\r`, `\n`, `\0`, or any C0 control other than HTAB. This applies at capture time and again before any outbound use. `change-user-agent` is never copied into an outbound request without re-validation. (Defense in depth: `HttpClient` also rejects these, but MyVpn must not depend on that alone, and the rejection must be recorded as a security issue.)

**A5 — Length and count limits.** Enforce §2.8 before parsing. Oversize ⇒ reject with `header.oversize`; never truncate a security-sensitive value into validity. Display-only strings may be truncated for rendering *after* validation, with an explicit flag.

**A6 — URL safety (SSRF / open redirect / deeplink).**
- Accept only `https` for `new-url`, `fallback-url`, `support-url`, `profile-web-page-url`, `check-url-via-proxy`, `server-address-resolve-dns-domain`. (`http` only if the user explicitly enabled plaintext for that subscription; default reject.)
- Reject URLs with embedded credentials (`user:pass@`), `file:`, `javascript:`, `data:`, `happ:`, `tg:`, and unknown schemes — except that `sub-info-button-link` may be *displayed* as a button, and only `https`/`tg` schemes may actually be opened, and only on user click.
- Do **not** auto-contact `new-url`/`fallback-url`. URL migration is a Gate B proposal.
- Never resolve/fetch a provider-supplied URL from a background task without user consent; block loopback, link-local, and RFC1918 targets unless the subscription host itself is in those ranges.

**A7 — Secrets.** `socks-auth-password`, `http-auth-password` are secrets: never logged, never shown raw in the audit trail, redacted in diagnostics, stored with the same protection as other credentials. `change-user-agent` is not a secret but is bounded and control-character checked.

**A8 — No network egress from a header.** Except: the user-initiated subscription fetch itself, and an explicitly-confirmed `fallback-url`. Notably MyVpn does **not** implement the `providerid` daily call to `check.happ-proxy.com` (third-party telemetry, carrying HWID and OS version) unless a user opts in with a clear description. Even then it is off by default.

**A9 — No execution / no filesystem.** Header values never become paths, process arguments, registry values, environment variables, or template fragments. `routing` profiles referencing `Geoipurl`/`Geositeurl` are not downloaded without consent.

**A10 — No state mutation from parsers.** Enforced structurally: parsers return records; only the application-policy layer touches settings, and only for Gate A. Gate B changes go through a persisted, revocable consent record keyed by `(subscriptionId, fieldId, valueHash)` so a provider cannot flip a value later without re-prompting.

**A11 — Confirmation binding.** A Gate B confirmation is bound to the exact proposed value (hash). If the provider later sends a different value, MyVpn re-prompts. This defeats "confirm once, then change silently".

**A12 — Failure isolation.** A malformed header must not abort the subscription refresh. A malformed `encrypt-tag` must abort it (fail closed on integrity).

### 3.3 Risk register

| ID | Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| R1 | Provider uses `custom-tunnel-config`/`routing` to reroute or exfiltrate traffic | Med | High | Gate C default; Gate B only with schema allow-list + diff UI |
| R2 | `change-user-agent` CRLF injection into outbound request | Low | High | A4 control-char rejection at capture and at use |
| R3 | `new-url`/`new-domain` silently repoints the subscription to an attacker host | Med | High | A6: https-only, no auto-migration, Gate B, re-prompt on change |
| R4 | `sub-info-button-link` deeplink auto-open (`javascript:`, `file:`, custom scheme) | Low | High | A6 scheme allow-list; user-click only |
| R5 | Spoofed `profile-title` / `announce` via RTL override, zero-width, homoglyph | Med | Med | A: strip bidi/zero-width/controls; cap length; render as plain text |
| R6 | Forged `subscription-userinfo` (fake unlimited / far-future expiry) | Med | Low–Med | Display-only; label as provider-reported; never gate features on it |
| R7 | Duplicate-header smuggling (`subscription-userinfo` twice, different values) | Low | Med | A2 reject-on-conflict |
| R8 | Oversized headers ⇒ memory/CPU DoS | Low | Med | A5 + §2.8 limits + parse budget |
| R9 | `providerid` telemetry leaks HWID/OS without consent | Med (if implemented) | Med | A8: do not implement by default; explicit opt-in |
| R10 | `color-profile` / JSON bombs (deep nesting) | Low | Med | §2.9 bounded reader; depth/token caps |
| R11 | Header/body precedence confusion (`#subscription-userinfo:` vs header) | Med | Low–Med | Reject on conflict; never merge |
| R12 | Unknown header later becomes a setting via careless "generic mapper" | Low | High | I2/I3 + type-level separation + explicit test |
| R13 | Malicious `exclude-routes-set` routes all traffic around the tunnel | Med | High | Gate B, destructive-semantics warning |
| R14 | Credential headers (`*auth-password`) logged | Low | High | I10 redaction + audit test |
| R15 | `fallback-url` used as an SSRF pivot | Low | Med | A6 target checks; user consent |

---

## 4. Implementation plan

Phased; each phase independently shippable and testable. No `src/` changes were made by this research task.

**Phase 0 — Skeleton and limits (0.5 d)**
1. Add `src/MyVpn.Subscriptions/Headers/` with `RawHeaderBag`, `RawHeaderEntry`, `HeaderParseContext`, `HeaderLimits`, `ParseResult`, `ValidationIssue`, `ParseOutcome`.
2. Implement bounded capture with A4/A5 enforcement and truncation flags.
3. Implement `UnknownHeaderStore` with fingerprints.
4. Unit tests for capture limits and control-character rejection.

**Phase 1 — Registry and contracts (0.5 d)**
1. `ISubscriptionHeaderParser`, `HeaderGate`, `DuplicatePolicy`.
2. `SubscriptionHeaderParserRegistry` with total ordering, budget, try/catch isolation, freeze-after-composition.
3. `SubscriptionMetadata` builder + `Maybe<T>`.
4. Tests: ordering determinism, exception isolation, absent/invalid semantics.

**Phase 2 — Gate A parsers (1.5 d)**
`profile-title`, `content-disposition`, `subscription-userinfo`, `announce` + `sub-info-*` + `sub-expire*`, `support-url`, `profile-web-page-url`, `ping-result`, `subscriptions-sort-type`, `subscription-pin`, `color-profile` (bounded), the boolean/scheduling preference set.
Tests: golden fixtures per §6.

**Phase 3 — Gate B parser set (2 d)**
Emit `PendingChange` for routing/TUN/DNS/proxy/app-list/URL/credential/UA headers. No application code. Preserve the `tun-enable`/`proxy-enable` exclusivity check and `exclude-routes-set` destructive flag.
Tests: every Gate B header produces exactly one `PendingChange` and zero setting mutations.

**Phase 4 — Gate C + transport-critical (1 d)**
1. `encrypt-tag` consumer in the transport layer (strict Base64, 16 bytes, AES-128-GCM, IV `kkkkkkkkkkkk`, key by `?key=` id).
2. `custom-tunnel-config` and `routing` refusal paths with security notices.
3. `providerid` recognized-and-ignored (recorded, never acted on) unless an opt-in telemetry feature exists.

**Phase 5 — Consent UX and persistence (2 d)**
Diff-style review screen; per-`(subscription, field, valueHash)` consent records; revocation; "reset provider overrides" action. Gate A changes apply silently but are listed in a per-subscription "provider settings" page.

**Phase 6 — Body-comment parity (1 d)**
Reuse the same parsers against `#name: value` lines; implement conflict rejection between channels.

**Phase 7 — Hardening and fuzzing (1 d)**
Property-based fuzz harness, CI gates, audit-log redaction verification, performance budget assertions.

**Phase 8 — Docs and rollout (0.5 d)**
Document the supported header set and the refusal list in user-facing docs; feature-flag Gate B in stages (display-only first, then prompts).

---

## 5. Files/modules affected (`src/MyVpn.*`)

Proposed new project and touch-points. Names are proposals; align with the existing solution layout when it lands.

```
src/MyVpn.Subscriptions/                          (new project)
  MyVpn.Subscriptions.csproj
  Headers/
    RawHeaderBag.cs
    RawHeaderEntry.cs
    HeaderLimits.cs
    HeaderParseContext.cs
    ISubscriptionHeaderParser.cs
    HeaderGate.cs
    DuplicatePolicy.cs
    SubscriptionHeaderParserRegistry.cs
    SubscriptionMetadata.cs
    SubscriptionMetadataBuilder.cs
    Maybe.cs
    ParseResult.cs
    ParseOutcome.cs
    ValidationIssue.cs
    PendingChange.cs
    RefusedDirective.cs
    UnknownHeaderStore.cs
    Parsers/
      GateA/
        ProfileTitleParser.cs
        ContentDispositionParser.cs
        SubscriptionUserInfoParser.cs
        AnnouncementParser.cs           // announce + sub-info-* + sub-expire*
        SupportUrlParser.cs
        ProfileWebPageUrlParser.cs
        PingResultParser.cs
        SortTypeParser.cs
        PinParser.cs
        ColorProfileParser.cs
        PreferenceToggleParsers.cs      // auto-update, autoconnect, collapse, expand, etc.
      GateB/
        RoutingEnableParser.cs
        TunnelSelectionParser.cs        // tun-enable/proxy-enable/tun-type/tun-mode/xray-tun-*
        RouteExclusionParser.cs         // exclude-routes, -set
        DnsOverrideParser.cs
        PerAppProxyParser.cs
        FragmentationParser.cs
        NoisesParser.cs
        MuxParser.cs
        UserAgentOverrideParser.cs      // change-user-agent, manual-block-user-agent
        LocalProxyAuthParser.cs         // socks-auth-*, http-auth-*
        UrlMigrationParser.cs           // new-url, new-domain, fallback-url
        MiscBehaviorParser.cs           // sniffing, inbound-http, block-bind, app-auto-start, hwid
      GateC/
        CustomTunnelConfigParser.cs     // parse-to-refuse, bounded JSON
        RoutingLinkParser.cs            // happ://routing/... -> refuse/consent
        ProviderIdParser.cs             // recognize + ignore, no egress
  Transport/
    SubscriptionTransport.cs            // capture, limits, redirect policy
    EncryptTagHandler.cs                // AES-128-GCM, IV kkkkkkkkkkkk
    SubscriptionContentSniffer.cs
  Body/
    SubscriptionBodyCommentParser.cs    // "#name: value" reuse of the same parsers
  Security/
    HeaderValueSanitizer.cs             // CR/LF/C0, bidi, zero-width
    UrlSafetyValidator.cs               // scheme/host/SSRF rules
    RedactionPolicy.cs

src/MyVpn.App/                                    (touch)
  Subscriptions/ProviderSettingsReviewViewModel.cs
  Subscriptions/ProviderSettingsReviewView.*
  Subscriptions/ConsentStore.cs (or in Core)

src/MyVpn.Core/                                   (touch, if it owns persistence)
  Subscriptions/ProviderConsentRecord.cs
  Subscriptions/SubscriptionMetadataStore.cs

tests/MyVpn.Subscriptions.Tests/                  (new)
  Headers/RegistryTests.cs
  Headers/LimitsTests.cs
  Headers/UnknownHeaderTests.cs
  Headers/Parsers/GateA/*.cs
  Headers/Parsers/GateB/*.cs
  Headers/Parsers/GateC/*.cs
  Headers/Fixtures/**.json
  Headers/Fuzz/HeaderFuzzTests.cs
  Transport/EncryptTagTests.cs
  Body/BodyCommentParityTests.cs
  Security/UrlSafetyTests.cs
  Security/RedactionTests.cs
```

Dependency direction: `MyVpn.Subscriptions` must not reference the tunnel, core, or UI. Gate B values leave as data; `MyVpn.App` decides. This is what prevents parsers from mutating unrelated state.

---

## 6. Tests

### 6.1 Fixture format (golden files)

```jsonc
{
  "id": "userinfo/valid-classic",
  "description": "Classic panel userinfo",
  "response": {
    "status": 200,
    "requestUri": "https://example.com/sub/abc",
    "headers": {
      "content-type": ["text/plain"],
      "subscription-userinfo": ["upload=0; download=2153701362; total=0; expire=1790951622"],
      "profile-title": ["base64:SGFwcCB0aGUgYmVzdCE="]
    }
  },
  "expect": {
    "outcomes": { "defacto.subscription-userinfo": "Parsed", "happ.profile-title": "Parsed" },
    "metadata": {
      "title": "Happ the best",
      "usage": { "upload": 0, "download": 2153701362, "total": 0, "isUnlimited": true }
    },
    "issues": [],
    "unknownHeaders": []
  }
}
```

Every parser gets fixtures in five buckets: **valid**, **boundary**, **invalid**, **malicious**, **unicode**.

### 6.2 Required test categories

1. **Valid sets.** One fixture per documented header, each asserting `Outcome = Parsed` and the exact typed value. Coverage target: all 61 header-deliverable parameters plus `providerid`, `routing`, `encrypt-tag`, `content-disposition`.
2. **Invalid sets.**
   - Unknown enum value (`tun-type: wireguard`).
   - Out-of-range integers (`xray-tun-mtu: 70000`, `proxy-ping-timeout: 99`, `mux-tcp-connections: 99999`).
   - Negative traffic (`upload=-1`).
   - Malformed userinfo: missing `=`, missing key, stray `;`, `upload=abc`, `expire=99999999999999999999` (overflow), duplicated key within one value, float values, empty value.
   - `profile-title` > 25 chars (plain and base64), invalid base64, base64 with trailing garbage.
   - `announce` > 200 chars; `sub-info-text: 0` sentinel handling.
   - Bad lists: `exclude-routes` with hostnames, malformed CIDR, > cap items; `per-app-proxy-list` with invalid package IDs.
   - `tun-enable` + `proxy-enable` both present ⇒ rejected pair.
3. **Malicious sets.**
   - CRLF: `profile-title: x\r\nSet-Cookie: a=b`, `change-user-agent: x\r\nX-Injected: 1`, bare `\n`, `\0`, VT, FF.
   - `sub-info-button-link: javascript:alert(1)`, `file:///etc/passwd`, `tg://` (allowed to display, must not auto-open), `http://169.254.169.254/` (SSRF).
   - `new-url: http://attacker.example/` (scheme), `new-url: https://user:pass@attacker/` (credentials), `new-url` to loopback.
   - `custom-tunnel-config` containing a huge nested object, a `log` path, or an outbound to an attacker proxy ⇒ **must be refused, must not reach any core**.
   - `routing: happ://routing/onadd/<base64 with Geoipurl=http://...>` ⇒ refused/consent, no fetch.
   - `color-profile` JSON bomb (depth 1000), wrong field types, extra fields.
   - `providerid` present ⇒ assert **no outbound request** is made.
   - Bidi/RTL override, zero-width joiner, `U+202E` in `profile-title`/`announce`/`sub-info-text` ⇒ stripped.
4. **Oversized.**
   - Single value at limit, limit+1, limit×100.
   - Header count at/over `MaxHeaderCount`.
   - Total header bytes over `MaxTotalHeaderBytes`.
   - `custom-tunnel-config` over `MaxValueBytes` for JSON headers.
   - Assert: no OOM, no long parse, correct `header.oversize` issue, truncation flag where display-only.
5. **Unicode.** Titles/announces with emoji (Happ documents emoji in titles), CJK, combining marks, invalid UTF-8 bytes, lone surrogates, and the documented rule that **UTF-8 percent-encoded emoji are not supported in subscription headers** ([emoji](https://www.happ.su/main/dev-docs/emoji)) — assert percent-encoded emoji in a header is left literal, not decoded into an icon.
6. **Duplicate headers.**
   - `subscription-userinfo` twice, identical ⇒ accepted once.
   - `subscription-userinfo` twice, differing ⇒ rejected (`header.duplicate-conflict`), no numeric merge.
   - `profile-title` twice, differing ⇒ rejected.
   - Compatibility spelling: `Subscription-Userinfo` and `subscription-userinfo` together (case-insensitive match) ⇒ treated as a duplicate.
   - `exclude-routes` twice ⇒ joined under `JoinList` policy, then validated.
   - CamelCase vs lowercase (`Profile-Update-Interval`) ⇒ matched.
7. **Malformed userinfo.** Dedicated fixture family (see invalid set) plus: extra unknown keys preserved in `ExtensionPairs`; whitespace variants `upload = 0 ; download=1`; `;`-trailing; empty header value ⇒ `Unspecified`, never `0`.
8. **Unknown header preservation.**
   - A response with only `x-vendor-foo: bar` and `x-vendor-blob: <2 KiB>` ⇒ `Metadata` has zero settings; `UnknownHeaders` contains both; blob truncated to `MaxUnknownValueBytes` with `ValueTruncated = true`.
   - Assert unknown headers are **not** written to any settings store, **not** passed to the core, and **not** fully logged (fingerprint only).
   - Assert `MaxUnknownHeaders` cap and deterministic ordering.
9. **Fuzz-style tests.**
   - Corpus = all golden fixtures.
   - Mutators: random byte flip, random byte insert/delete, duplicate/remove random header, replace value with random bytes, random case changes in names, random-length values up to 256 KiB, random Unicode.
   - Properties (assert on every iteration, e.g. 10k iterations or a fixed seed set for CI):
     - no unhandled exception escapes `ParseAll`;
     - every returned value satisfies its declared schema and bounds;
     - `ParseAll` is deterministic (same input ⇒ same output);
     - total parse time stays within `ParseBudget`;
     - **no Gate B field ever lands in an applied setting** — only `PendingChanges`;
     - **no Gate C field is ever applied**;
     - `UnknownHeaders` never appears in settings;
     - memory bounded (allocation ceiling assertion).
   - Use a fixed corpus seed in CI plus a nightly run with a random seed.
10. **Cross-channel parity.** Same header delivered as `#name: value` body comment ⇒ identical `ParseResult`; header + body with differing values ⇒ conflict issue, nothing applied.
11. **Transport/`encrypt-tag`.** Correct tag decrypts known vector; wrong length, non-base64, valid-base64-wrong-length, and tampered tag all reject the whole response; tag never accepted concatenated with ciphertext.
12. **Redaction.** Assert `socks-auth-password`/`http-auth-password` values never appear in any audit record, log capture, or exception message.
13. **No-egress assertions.** Using a fake `HttpMessageHandler`: `providerid`, `new-url`, `fallback-url`, `routing`, `check-url-via-proxy`, `server-address-resolve-dns-domain`, and `sub-info-button-link` produce **zero** additional requests during parse and apply.

### 6.3 CI gates

- All fixtures green; zero skipped fuzz seeds.
- Public API snapshot test so `SubscriptionMetadata` cannot silently gain an applied Gate B field.
- A test that enumerates every parser's `Gate` and asserts the Gate-B/C sets match the allow-lists in §2.5 (guards against a new parser defaulting to Gate A).
- An architecture test asserting `MyVpn.Subscriptions` has no reference to core/tunnel/UI assemblies.

---

## 7. Licensing

- **Implemented from public documentation only.** The header names, value formats, and semantics in this report come from Happ's public developer documentation at `https://www.happ.su/main/dev-docs` and its Markdown mirrors, plus publicly documented de-facto conventions from third-party projects' *documentation*.
- **No proprietary or closed-source client code was read, copied, decompiled, or transcribed.** Happ is a closed-source client; none of its application code, binaries, or internal formats were used. Nothing in this report is a derivative work of Happ's source.
- Code sketches in §2 are original design artifacts authored for MyVpn. They were not copied from Happ or from any third party.
- **De-facto header conventions** (`subscription-userinfo` and friends) are implemented from public documentation. Where a third-party project documents them under a copyleft license (e.g. Marzban's docs are published by the Gozargah project alongside an AGPL-3.0 codebase, and the mirror at marzban-docs.sm1ky.com is community-run), MyVpn re-implements the *wire format* from the documentation. Wire protocols and header formats are not copyrightable subject matter; nevertheless, **no source code from these projects is to be copied into MyVpn**. If a future task proposes porting code, the license must be reviewed and attribution added first.
- **Trade names.** "Happ", "Marzban", "Clash", "Stash", "sing-box", "Xray" are used descriptively for interoperability. MyVpn must not present itself as affiliated with or endorsed by any of them, and must not ship their logos or trademarks.
- **Test vectors.** Fixtures authored for this project; the `encrypt-tag` test must use a key generated for the test, not the publicly documented `key02` test key in production paths (that key is documented as a *test* key at <https://www.happ.su/main/dev-docs/encrypting-subscription-content> and must never be relied on for real subscriptions).
- **Personal data.** `providerid`-style telemetry carries HWID and OS version; MyVpn does not implement it by default (§3.2 A8), which also keeps MyVpn clear of the data-processing questions that feature raises.

---

## Appendix A — Definitive header list (compact)

**Happ-documented (lowercase spellings; match case-insensitively):**

- Identity/display: `profile-title` (≤25 chars, plain|`base64:`), `content-disposition` *(UNVERIFIED as a Happ parameter)*
- Usage: `subscription-userinfo` → `upload=…; download=…; total=…; expire=…`
- Links: `support-url`, `profile-web-page-url`, `new-url`, `new-domain`, `fallback-url`
- Announcements: `announce` (≤200), `sub-info-color`, `sub-info-text`, `sub-info-button-text`, `sub-info-button-link`, `sub-expire`, `sub-expire-button-link`, `notification-subs-expire`
- Scheduling: `profile-update-interval` (hours), `subscription-auto-update-enable`, `subscription-auto-update-open-enable`, `subscription-request-timeout` (5–15 s)
- Routing/TUN: `routing`, `routing-enable`, `custom-tunnel-config`, `tun-enable`, `proxy-enable`, `tun-type`, `tun-mode`, `xray-tun-enable`, `xray-tun-mtu` (68–65535), `exclude-routes`, `exclude-routes-set`, `include-all-networks-enable`, `exclude-local-networks-enable`, `exclude-apns-enable`, `dns-from-json-enable`, `block-bind-to-tunnel-enable`, `hide-vpn-icon`
- Per-app (Android): `per-app-proxy-mode`, `per-app-proxy-list`, `per-app-proxy-list-invert`, `per-app-proxy-list-set`
- Transport tuning: `fragmentation-enable`, `fragmentation-packets`, `fragmentation-length`, `fragmentation-interval`, `fragmentation-maxsplit`, `noises-enable`, `noises-packet-type`, `noises-packet`, `noises-delay`, `noises-rand`, `noises-rand-range`, `mux-enable`, `mux-tcp-connections`, `mux-xudp-connections`, `mux-quic`, `sniffing-enable`, `inbound-http-enable`, `no-limit-enabled`, `no-limit-xhttp-enabled`
- Local proxy auth: `socks-auth-mode`, `socks-auth-user`, `socks-auth-password`, `http-auth-mode`, `http-auth-user`, `http-auth-password`
- Client behaviour: `change-user-agent`, `manual-block-user-agent`, `app-auto-start`, `subscription-autoconnect`, `subscription-autoconnect-type`, `subscription-ping-onopen-enabled`, `ping-type`, `ping-result`, `check-url-via-proxy`, `proxy-ping-timeout` (5–15 s), `proxy-ping-mode`, `subscriptions-sort-type`, `subscriptions-collapse`, `subscriptions-expand-now`, `subscription-pin`, `hide-settings`, `dont-use-filter`, `color-profile`, `user-agent-geo-files`, `server-address-resolve-enable`, `server-address-resolve-dns-domain`, `server-address-resolve-dns-ip`
- Privacy: `subscription-always-hwid-enable`, `subscription-alternative-hwid-enabled`, `providerid`
- Integrity: `encrypt-tag` (Base64 AES-128-GCM tag; body is ciphertext; `?key=` in URL)

**De-facto convention (not Happ-documented as such):** CamelCase aliases `Subscription-Userinfo`, `Profile-Update-Interval`, `Profile-Web-Page-Url`; `Content-Disposition: attachment; filename="<profile name>"`; units for `subscription-userinfo` (bytes / Unix seconds), `total=0` = unlimited, `expire=0` = no expiry, float values accepted.
