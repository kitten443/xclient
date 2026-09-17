# ADR-0001 — Record architecture decisions

- **Status:** Accepted
- **Date:** 2026-09-16
- **Deciders:** MyVpn maintainers
- **Supersedes:** —
- **Superseded by:** —

## Context

MyVpn is a from-scratch, clean-room reimplementation of an Xray-core desktop VPN
client. Its design is heavily informed by prior art (v2rayN, Xray-core, Happ,
Wintun) and by a body of primary-source research already committed to
`docs/research/`. Several of the load-bearing decisions are counter-intuitive
and easy to "fix" back into a broken state by a well-meaning later change:

* the native Xray TUN inbound only exists above a version floor, and one release
  inside the supported range has an incompatible `mtu` field type;
* the root cause of v2rayN issue #9765 was *not* a relative path, so a guard
  against relative paths does not address it;
* on Windows and macOS the honest answer to "per-process tunnelling" is
  "not achievable for a self-distributed client", and a future contributor will
  be tempted to implement it anyway;
* `Xray`'s "UDP FullCone" has no JSON key and is a server-side egress property;
* subscription headers are attacker-influenced input and must not be able to
  change routing.

Without a written record, each of these is re-litigated from scratch or, worse,
silently reversed. The research reports are long (≈9,200 lines) and are evidence
archives rather than decisions; they answer "what is true", not "what MyVpn will
do about it".

## Decision

We will record every architecturally significant decision as an ADR in
`docs/adr/`, using the format **Title, Status, Context, Decision, Consequences,
Alternatives considered, References**.

Rules:

1. One decision per ADR. A decision that changes is *superseded* by a new ADR,
   not edited in place; the superseded record keeps its history.
2. Every ADR cites its grounding: the relevant `docs/research/NN-*.md` section
   **and** the underlying primary source (upstream file, tag, man page, RFC,
   vendor documentation). "We think" is not a reference.
3. Every ADR records what it explicitly *refuses* to promise, and names the
   verification still outstanding. An ADR that hides an unverified assumption is
   worse than no ADR.
4. Facts that were verified against a primary source are stated as facts; facts
   that were not are marked **UNVERIFIED**. The distinction is preserved from the
   research reports rather than flattened.
5. Implementation state is tracked outside the ADR (see
   `docs/architecture/overview.md`, "Implemented vs planned"); an accepted ADR
   does not imply the code exists yet.

## Consequences

**Positive**

* The verified version floors, field names, licence facts and capability limits
  are written down once and can be cited from code comments, CI comments and
  review discussions.
* A regression such as "re-introduce `autoRoute` into the TUN config" or
  "auto-apply `custom-tunnel-config`" becomes a documentation violation, not a
  matter of taste.
* Reviewers can distinguish a deliberate limitation from an oversight.

**Negative / costs**

* Eleven documents to keep current; the index below must be updated when an ADR
  is added or superseded.
* Some ADRs (notably ADR-0006 and ADR-0007) record decisions whose *verification*
  is still outstanding; they must be revisited after the platform spikes rather
  than treated as settled truth.

**Neutral**

* ADR numbers are stable identifiers. `docs/adr/ADR-0004` is referenced from
  `Directory.Build.props`; `docs/adr/ADR-0009` from `NOTICE`; the CI workflow
  references ADR-0009 and this file.

## Index

| ADR | Title | Status | Decision in one line |
|---|---|---|---|
| [0001](ADR-0001-record-architecture-decisions.md) | Record architecture decisions | Accepted | ADRs are the durable decision record; every one cites a primary source. |
| [0002](ADR-0002-use-xray-core-only-native-tun.md) | Use Xray-core only, with the native TUN inbound | Accepted | Xray-core is the sole network core; TUN is Xray's native `"protocol": "tun"`; sing-box excluded; ≥ `v26.4.15`, reject `v26.4.13`, recommend `v26.9.9`; emit only the eight real TUN fields. |
| [0003](ADR-0003-geodata-asset-management.md) | Geo-data asset management | Accepted | Inject the asset directory through two independent channels, assert resolution before launch, validate structurally, install atomically, never emit a rule for an unusable asset. |
| [0004](ADR-0004-net8-platform-targeting.md) | Plain `net8.0` for every project | Accepted | No OS-specific TFMs; runtime capability probing; unsafe OS calls guarded by `RuntimeInformation`. |
| [0005](ADR-0005-privileged-helper-and-ipc.md) | Privileged helper and local IPC | Accepted | The UI is never elevated; privileged work lives in a narrow, authenticated, typed-command service. |
| [0006](ADR-0006-killswitch-per-platform.md) | Per-platform kill switch | Accepted | Windows: WFP via `fwpuclnt.dll`, one max-weight sub-layer; Linux: single-transaction nftables; macOS: PF anchors, with Apple's "PF is not API" caveat stated. |
| [0007](ADR-0007-process-routing-capability-matrix.md) | Per-process routing capability matrix | Accepted | Publish an honest per-platform capability table; refuse to promise unreliable functionality, including any per-process tunnelling on macOS. |
| [0008](ADR-0008-subscription-header-safety.md) | Subscription header safety | Accepted | Three gates; no header may influence routing, TUN, DNS or credentials automatically; empty toggle never folded to off. |
| [0009](ADR-0009-licensing-and-provenance.md) | Licensing and provenance | Accepted | v2rayN is GPL-3.0-only ⇒ clean-room; Xray MPL-2.0 consumed as a separate process; geo data from `v2fly`; only public Happ documentation. |
| [0010](ADR-0010-ui-localization-and-theming.md) | UI localization and theming | Accepted | DI-constructed view models, runtime culture switching, `ErrorCodes`-to-message-key mapping, theme swap by resource dictionary. |
| [0011](ADR-0011-transport-and-nat-strategy.md) | Transport and NAT strategy | Accepted | Cone is server-side and env-toggled; mux/XUDP coherence asserted; bounded fallback chain; local NAT type is never authoritative. |
| [0012](ADR-0012-connect-sequencing-and-verification.md) | Connect sequencing and verification | Accepted | Arm the Kill Switch before starting the core; verify with a real request; a failed first connect returns to `Disconnected`; restore the proxy before tearing down the listener. |

## Alternatives considered

* **No ADRs; document decisions in code comments only.** Rejected: the decisions
  span projects, and code comments cannot be cited from CI policy or from
  `NOTICE`. The repository already contains comments that describe *planned*
  behaviour in the present tense (for example, `MyVpn.Ipc.csproj` describes the
  transport and peer-credential verification as if implemented); a prose record
  with an explicit implementation-state table is the corrective.
* **A single `docs/architecture/decisions.md`.** Rejected: one decision per ADR
  is what makes supersession and citation tractable.
* **Copy the research reports into ADRs.** Rejected: the reports are evidence,
  not decisions, and duplicate maintenance would let them drift.

## References

* `docs/research/` — the eight research reports, cited individually by the ADRs
  below.
* `NOTICE` §3 — the clean-room and provenance policy this ADR formalises.
* `Directory.Build.props` — already references `docs/adr/ADR-0004`.
* ADR format: M. Nygard, *Documenting Architecture Decisions* (2011),
  <https://cognitect.com/blog/2011/11/15/documenting-architecture-decisions>.
