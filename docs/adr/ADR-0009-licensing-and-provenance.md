# ADR-0009 — Licensing and provenance

- **Status:** Accepted
- **Date:** 2026-09-16
- **Deciders:** MyVpn maintainers
- **Supersedes:** —
- **Superseded by:** —
- **Implementation status:** Implemented as policy: `NOTICE` and `LICENSE` exist
  and are correct; the CI `provenance-guard` job and the packaging
  provenance-manifest step exist in `.github/workflows/ci.yml`. Geo-data
  download and Xray bundling are planned.

## Context

MyVpn is a from-scratch client whose design is heavily informed by prior art. The
licence position of every input determines what MyVpn may do, and the research
established facts that are easy to get wrong — several of them contrary to the
common assumption.

### v2rayN is GPL-3.0-**only**, not "or later"

* `/LICENSE` is the verbatim GNU GPL version 3 text with **no version-election
  statement** anywhere in the repository.
* v2rayN's `Directory.Build.props` declares the deprecated SPDX expression
  `GPL-3.0`, which is the alias of `GPL-3.0-only`, not `GPL-3.0-or-later`.
* GitHub repository metadata reports `spdx_id: "GPL-3.0"`.
* No `.cs` file carries an SPDX or copyright header; `README` has no licence
  section; there is no `NOTICE`/additional-terms file.

The consequence is that copying *anything* from v2rayN — source, the embedded
`Sample/*` JSON config templates, `.resx` strings, shell scripts, or icons —
would make MyVpn a derivative work of a GPL-3.0-only work, and the copied
portions stay GPL-3.0-only. MyVpn does not need to rely on any "or later"
permission to do this, because it grants none: our own `LICENSE` is also the bare
GPLv3 text with no version-election statement, and `PackageLicenseExpression` is
`GPL-3.0-only`. That alignment is deliberate — see `docs/provenance.md`. Prior art
that is only *studied* is not a licensing event at all; `NOTICE` §3 states the
policy and the register in `docs/provenance.md` records every adapted file.

### Xray-core is MPL-2.0 and is consumed as a separate process

MyVpn does not link against or modify Xray-core. It launches the unmodified
executable and speaks to it through a generated JSON configuration file and the
process's stdout/stderr. MPL-2.0 is file-level copyleft; using a separate
executable is the "Larger Work" case, so **MPL-2.0 imposes no licensing
obligation on MyVpn's own source code**. If MyVpn *bundles* the binary, MPL-2.0
§3.2 (make the Covered Software available in Source Code Form, tell recipients
how to obtain it) and §3.4 (keep upstream copyright/licence notices intact)
apply, which is why the bundle must ship the upstream `LICENSE` verbatim and
record the exact version and SHA-256.

### Geo data: the source choice is a licensing decision

`Loyalsoldier/v2ray-rules-dat` is v2rayN's default geo source and is
**GPL-3.0**. `v2fly/geoip` is **CC-BY-SA 4.0** and
`v2fly/domain-list-community` is **MIT**. `NOTICE` §2 already names the `v2fly`
sources — the right choice. CC-BY-SA still obliges attribution and ShareAlike for
any redistributed (or converted) copy.

### Wintun is two licences for two artefacts

The Wintun **source** is GPL-2.0
(`SPDX-License-Identifier: GPL-2.0`; the README says "Source code is licensed
under the GPLv2"; no "or later" wording was found, so treat it as
GPL-2.0-only). The **prebuilt, Microsoft-signed `wintun.dll`** is distributed
under a separate proprietary *Prebuilt Binaries License* shipped in the archive
as `LICENSE.txt` — it is neither GPL nor MIT. §3(d) permits redistribution only
"insofar as the Software is distributed alongside other software that uses the
Software **only via the Permitted API**" (the `wintun.h` interface set). The
licence forbids reverse-engineering, deriving works other than through the API,
stripping notices, and implying endorsement, and the grant is non-transferable.
The README is explicit: do not distribute drivers or files named "Wintun"
(they clash with official deployments); distribute `wintun.dll` as downloaded.

### Happ is proprietary; only its public documentation may be used

Happ is a closed-source client. `docs/research/05-happ-subscription-headers.md`
states that everything was derived from the public developer documentation at
<https://www.happ.su/main/dev-docs> and its Markdown mirrors, plus de-facto
conventions documented by third-party projects' *documentation*. No Happ code,
binary or internal format was read, copied, decompiled or transcribed.

### Other facts worth recording

* `GlobalHotKeys` (used by v2rayN) is **WTFPL v2** — not OSI-approved, which
  matters for corporate policy and licence-scanning tooling, and Windows-only.
  Not imported.
* WiX (the likely Windows installer toolchain) is **MS-RL, not MIT**, and WiX
  v6/v7 participate in the Open Source Maintenance Fee: organisations above a
  revenue threshold must sponsor the project. A compliance obligation with a
  cost, decided before the packaging toolchain is frozen.
* MyVpn's own NuGet dependency set (pinned in `Directory.Packages.props`) is
  MIT/Apache-2.0 only, and `NOTICE` §4 promises a machine-readable dependency
  inventory from the CI `license-scan` job. That job id is now referenced by the
  workflow; keep it stable.

## Decision

### 1. MyVpn stays clean-room

No code, no embedded configuration template, no shell script, no resource string
and no icon is copied from v2rayN, sing-box or any other client.
The line is drawn at **behaviour and protocol facts**, which are not
copyrightable and are independently documented upstream (for example
"`XRAY_LOCATION_ASSET` names the asset directory", "`xray run -c <file> -test`
exists", "Xray's TUN inbound has these eight JSON keys"). A specific utility that
would be cheaper to copy (say, a SOCKS5 readiness probe) is reimplemented from
its own specification (RFC 1928) instead.

**Enforcement is automated, not aspirational.** The CI `provenance-guard` job
fails if anything under `src/` or `tests/`:

* contains the token `sing-box` (case-insensitive) — the excluded core must not
  be named at all;
* contains a v2rayN **path or identifier** (`2dust/v2rayN`, a `v2rayN.`/`v2rayN/`
  identifier, a `using`/`namespace`/`import`/`alias` of it, or a
  `ProjectReference`/`PackageReference`/`AssemblyName`/`RootNamespace` naming
  it);
* contains a bare `v2rayN` token on a **non-comment** line.

Prose citations in comments (the existing "v2rayN issue #9765" attributions in
`MyVpn.Core/Geo`) are **allowed and reported as a notice**, because they are
attribution and provenance, which this ADR requires rather than forbids. Only
`src/` and `tests/` are scanned; `docs/`, `LICENSE`, `NOTICE`, `README.md` and
the workflow itself legitimately name the studied projects and are outside the
scan roots by construction rather than by exclusion patterns.

### 2. Xray-core is consumed as a separate process; bundling is licence-bearing

* The binary is launched, never linked, and never modified.
* When MyVpn bundles it, the artifact ships the **upstream `LICENSE` verbatim**
  in a `licenses/` directory, and `artifacts/manifest.json` records the exact
  **version and SHA-256**.
* If MyVpn ever patches or builds Xray itself, those modified files stay
  MPL-2.0 and must be published. The decision today is: **do not fork.**
* The version is pinned to the recommended `v26.9.9` (ADR-0002), and the
  packaging job verifies the download against `build/xray-checksums.txt` when
  that pin file exists, raising a loud warning when it does not (an unrecorded
  binary must never ship).

### 3. Geo data comes from `v2fly`, and is not bundled in early releases

* Sources: `v2fly/geoip` (**CC-BY-SA 4.0**) and
  `v2fly/domain-list-community` (**MIT**) — never
  `Loyalsoldier/v2ray-rules-dat` (GPL-3.0).
* Geo data is treated strictly as a **data asset**: downloaded at runtime,
  verified against a recorded SHA-256, stored in a user-writable directory, and
  never compiled into an assembly or modified.
* Attribution and licence text travel with any redistributed copy, and the UI
  shows the attribution ("Geo data © v2fly contributors, CC-BY-SA 4.0").
* The first releases **do not bundle** geo data at all: it is fetched
  post-install from the manifest with SHA-256 verification, and a user-supplied
  path is allowed. This keeps GPL-3.0 and CC-BY-SA material out of the installer
  aggregate until the redistribution obligations are fully wired up.
* **UNVERIFIED:** the licences of `Loyalsoldier/geoip`,
  `MetaCubeX/meta-rules-dat` and `2dust/sing-box-rules`. None is used.

### 4. Wintun is bundled only as the pristine signed DLL

* Ship the **unmodified**, architecture-matched `wintun.dll` from
  <https://www.wintun.net/> together with its `LICENSE.txt` (Xray ships the same
  file as `LICENSE-wintun.txt`). Pin the version (0.14.1; archive SHA-256
  `07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51`) and verify
  the hash in CI.
* **Do not** ship a loose `.sys` or `.cat`: the official DLL embeds the signed
  driver, catalogue and INF as resources and extracts them itself.
* **Do not** rename, patch, reverse-engineer or build our own Wintun from
  source: an own build is no longer Microsoft-signed, will not load on modern
  Windows without our own attestation-signed catalogue, and the licence forbids
  modifying the binary and naming a derivative "Wintun".
* Where Xray's release archive is the source of the DLL, ship Xray's copy and
  **no second copy**, so there is exactly one Wintun artefact in the payload.

### 5. Only publicly documented Happ header formats are implemented

Header names, value formats and semantics come from the public Happ developer
documentation and from de-facto conventions documented by third parties. Wire
formats and header names are not copyrightable subject matter, and no Happ code
was read. The `encrypt-tag` test vector must use a **key generated for the
test**, never the publicly documented `test` key, which must never be relied on
for a real subscription. Trade names are used descriptively for interoperability
only; MyVpn does not present itself as affiliated with or endorsed by any of
them and ships no third-party logos.

### 6. Dependencies stay permissive and are inventoried

The NuGet set stays MIT/Apache-2.0. The CI `license-scan` job (the job id
`NOTICE` §4 references) produces `artifacts/licences/*.deps.json` plus the
authoritative central pin file, and fails if `NOTICE` or `LICENSE` is missing.
The Windows packaging toolchain choice (WiX MS-RL + possible Open Source
Maintenance Fee) is a recorded, deliberate decision rather than a default.

### 7. Every release records provenance

The packaging job writes `dist/<rid>/manifest.json` with the product, version,
RID, commit, run id, and the path and SHA-256 of every produced artefact, plus
the bundled Xray version, asset name and archive SHA-256. `NOTICE` §5 is the
redistribution checklist this implements.

## Consequences

**Positive**

* The licensing position of every input is decided and written down, including
  the two that are counter-intuitive (v2rayN is GPL-3.0-only; Wintun's prebuilt
  DLL is not GPL/MIT).
* The clean-room claim is enforced mechanically in CI rather than asserted in
  prose, and prose citations remain permitted so provenance is preserved.
* A release cannot ship an Xray or Wintun binary without a recorded version and
  hash, and cannot ship without `NOTICE`/`LICENSE`.

**Negative / costs**

* The provenance guard can fail a legitimate change (for example a comment
  naming v2rayN on a non-comment line, or a future file that genuinely needs the
  token). The carve-out is narrow on purpose; the fix is to reword or to widen
  the guard deliberately, not to delete it.
* Not bundling geo data means a first-run download and a first-run failure mode
  that bundling would avoid.
* If the project ever wants to reuse v2rayN material, no "or later" grant exists to
  cover it — neither upstream's nor ours — so the copied files must be marked
  `GPL-3.0-only` with the original copyright line. That is deliberately
  unattractive.
* Carrying a native third-party DLL means tracking its version and hash forever.

## Alternatives considered

* **Copy v2rayN's embedded Xray config templates** (fastest path to a working
  config). Rejected: they are part of a GPL-3.0-only work, and an embedded
  template copied verbatim imports GPL-3.0-only material into an assembly. It
  would also freeze v2rayN's own schema mistakes — it emits `"MTU"` rather than
  the documented `"mtu"`.
* **Rely on an "or later" grant to cover copied v2rayN code.** Rejected, and now
  moot: "or later" cannot be granted over a GPL-3.0-only component, and this
  repository grants no such permission for its own files either. The combined
  work is GPLv3 with every part pinned to `only`.
* **Ship "inspired by v2rayN" in `NOTICE` and treat that as sufficient.** The
  research is explicit that this "is **not** a substitute once code is copied."
  Hence automated enforcement.
* **Use `Loyalsoldier/v2ray-rules-dat` for geo data because it is the ecosystem
  default.** Rejected: GPL-3.0 data in the installer aggregate, for no functional
  gain over the `v2fly` sources MyVpn already names.
* **Bundle geo data in the installer.** Deferred, not rejected forever: it makes
  a clean first run possible, but it requires shipping CC-BY-SA attribution and
  ShareAlike material and is not needed for a foundation release.
* **Build Wintun from source to avoid the prebuilt licence.** Rejected: the
  resulting driver is unsigned and will not load on current Windows without an
  EV certificate and Microsoft attestation signing — a large recurring cost for
  no benefit over redistributing the signed DLL unmodified.
* **Fork Xray-core to fix a bug or add a field.** Rejected for now: MPL-2.0
  would then attach to the modified files and MyVpn would own a build pipeline,
  signing and release cadence. Feature gaps are instead gated by the version
  policy (ADR-0002).
* **Import `GlobalHotKeys`.** Rejected: WTFPL is not OSI-approved (corporate
  policy and scanner friction) and it is Windows-only, so a cross-platform
  client needs its own per-platform implementation anyway.
* **Skip the dependency inventory because the set is small.** Rejected:
  `NOTICE` §4 promises it and the packaging checklist depends on it.

## References

* `docs/research/01-v2rayn-architecture.md` §1.11 and §3.1 — **primary
  grounding** for the v2rayN licence facts (bare GPLv3, `GPL-3.0` SPDX
  expression, no "or later" statement, no SPDX headers, no `NOTICE` file), the
  Xray MPL-2.0 conclusion, the geo-source licences, the WTFPL `GlobalHotKeys`
  fact, and the recommendation to make the clean-room boundary auditable with a
  CI check.
* `docs/research/05-happ-subscription-headers.md` §7 and §2.9 — public
  documentation only; no proprietary code read; the `test`-key caveat; the
  trade-name statement.
* `docs/research/06-windows-networking.md` §1.2.1 — the Wintun two-licence
  facts, the prebuilt-binary licence terms, the "do not ship `.sys`/`.cat`"
  constraint, the published 0.14.1 archive SHA-256, and the WiX MS-RL +
  Open Source Maintenance Fee note.
* `docs/research/03-xray-tun-inbound.md` "Pinned sources" — the vendored-upstream
  expectations for Xray (release asset naming is the packaging job's concern).
* `NOTICE` — the third-party notice and provenance statement this ADR
  formalises (§1 Xray, §2 geo data, §3 studied reference projects, §4 NuGet
  dependencies and the `license-scan` job, §5 the redistribution checklist).
* `LICENSE` — GPL-3.0.
* `Directory.Build.props` — `PackageLicenseExpression` `GPL-3.0-only`.
* `.github/workflows/ci.yml` — the `provenance-guard`, `license-scan` and
  `packaging` (provenance manifest) jobs.
* Upstream: <https://github.com/2dust/v2rayN> (LICENSE, `Directory.Build.props`);
  <https://github.com/XTLS/Xray-core> (MPL-2.0);
  <https://github.com/v2fly/geoip> (CC-BY-SA 4.0);
  <https://github.com/v2fly/domain-list-community> (MIT);
  <https://www.wintun.net/> (`prebuilt-binaries-license.txt`);
  <https://www.happ.su/main/dev-docs>.
* ADR-0002 (Xray-only, native TUN), ADR-0003 (geo-data management),
  ADR-0008 (header safety).
