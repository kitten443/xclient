# ADR-0010 — UI localization and theming

- **Status:** Accepted
- **Date:** 2026-09-16
- **Deciders:** MyVpn maintainers
- **Supersedes:** —
- **Superseded by:** —
- **Implementation status:** Planned. `MyVpn.Core/Settings/AppSettings.cs`
  already models the settings (`AppLanguage`, `AppTheme`, `UiDensity`, `UiScale`,
  `AccentColor`, `Validate()`), and `MyVpn.UI.csproj` already embeds
  `Localization/locales/*.json` and `Assets/**` and enables compiled bindings —
  but no view models, views, localizer or theme service exist yet.

## Context

The prior art's UI layer is the clearest source of avoidable debt in the whole
study (`docs/research/01-v2rayn-architecture.md` §1.8, §1.10). The specific
failures, and why they matter for a localization/theming decision:

* **Global mutable state everywhere.** Every view model inherits a base class
  with a `protected static Config? _config` field, and composition is a
  `Lazy<T>` singleton graph (`AppManager.Instance`) rather than a DI container.
  Deterministic tests are impossible without deep stubbing.
* **Theming by accumulation.** Changing font size or family **appends a new
  `Style` to `Application.Current.Styles` on every change** and never removes
  the previous one. Styles leak, and the visual result depends on how many times
  the user opened the settings page.
* **Localization that needs a restart.** Strings are compiled `.resx` values
  consumed as `{x:Static resx:ResUI.Key}`. `x:Static` resolves once when the
  view is loaded, so switching language sets `CurrentUICulture` and then shows a
  "restart required" notice. Nine languages are shipped, and switching between
  them is a restart.
* **Errors as log text.** Many failure paths are `catch { }` or
  `Logging.SaveLog(...); return null;`, and the message surfaced is a raw,
  unlocalized technical string. `MyVpn.Core` already rejects this by design:
  `MyVpnError` carries a `MessageKey` and arguments, and `ErrorCodes` values are
  explicitly documented as never-localized machine identifiers.
* **Settings with no single writer.** A mutable POCO tree is saved from 20 call
  sites across the codebase, and credentials sit in plaintext next to the
  profiles.
* **Two XAML trees** (WPF and Avalonia) for one product, with view models
  carrying window sizes, column widths and dialog interfaces because the Views
  are duplicated.

`AppSettings` is already an immutable record with a `SchemaVersion`, nested
validating records and a `Validate()` that aggregates errors. `MyVpn.UI.csproj`
already sets `AvaloniaUseCompiledBindingsByDefault` and already embeds
`Localization/locales/*.json`. `Directory.Packages.props` already pins
`CommunityToolkit.Mvvm` 8.4.0, `Avalonia` 11.2.3 and
`Microsoft.Extensions.Hosting`. The scaffolding has made the good choices; this
ADR records the rules that keep them.

## Decision

### MVVM and composition

* **`CommunityToolkit.Mvvm`** with `[ObservableProperty]` / `[RelayCommand]`
  source generators is the MVVM framework. It is MIT, has no runtime
  reflection/activation model, and keeps view models plain classes. (ReactiveUI
  is also MIT — licence is not the reason; simplicity and testability are.)
* **All view models are constructed by DI** (constructor injection) through a
  `Microsoft.Extensions.Hosting` generic host. There is **no static mutable
  state and no `AppManager.Instance`**: a view model receives its dependencies,
  and cross-view-model notification goes through `IMessenger`, never a static
  event.
* `IServiceCollection` composition is modular per layer
  (`AddMyVpnCore`/`AddMyVpnApplication`/`AddMyVpnInfrastructure`/`AddMyVpnPlatform`)
  and options are bound from settings via `IOptions<T>`.
* One View per ViewModel, registered in an `IDataTemplate` view locator, with
  compiled bindings (already enabled). Views contain no logic beyond visual
  wiring. There is exactly one XAML tree.
* Every failure is a typed state built from a `MyVpnError`, not a log line.

### Localization

* Strings live in **JSON locale files** under `Localization/locales/`, embedded
  as resources (already configured in `MyVpn.UI.csproj`), behind an
  `ILocalizer` abstraction consumed by a markup extension
  (`{loc:Translate Key}`) that subscribes to a culture-changed signal and
  re-reads its value.
* **Switching language takes effect without a restart.** This is the explicit
  corrective to `x:Static`: the localizer raises a change notification and
  bound strings update. No "restart required" notice exists in the product.
* `AppLanguage` (`System`, `English`, `Russian`, `SimplifiedChinese`) is the
  setting; `System` follows the OS UI culture. Missing keys fall back to the
  invariant/English value and are reported by a test that enumerates every
  key used in the code against every shipped locale — a missing translation is a
  test failure, not a runtime fallback.
* **Error text is always resolved from a message key.** `ErrorCodes` values are
  machine identifiers and are never localized; `MyVpnError.MessageKey` plus
  `Arguments` produce the user-facing sentence. A user must never see raw
  technical text such as `Asset initialization failed` or an exit code without
  an explanation, and — per ADR-0003 — must never see a raw Xray error.

### Theming

* Fluent theme plus `ThemeVariant` for `System` / `Light` / `Dark`, driven by
  `AppTheme`.
* A single `IThemeService` applies a theme by **swapping a resource
  dictionary** (and setting the variant) and never by appending to
  `Application.Current.Styles`. Font size, font family, density
  (`UiDensity.Comfortable` / `Compact`), `UiScale` and `AccentColor` are
  resource values that are replaced, so the UI state is a function of the
  settings value rather than of the edit history.
* Theme and language changes are applied by the same mechanism and are
  idempotent: applying the same settings twice produces the same visual tree.

### Settings

* A single `IAppSettingsStore` with a **single writer** (an actor/queue) writes
  atomically (temp file + `File.Move`), which is the pattern v2rayN already uses
  for its JSON config and which is the correct one.
* `AppSettings.SchemaVersion` is honoured: explicit, tested migrations, no
  in-place schema surgery from call sites.
* `AppSettings.Validate()` aggregates **all** offending fields so the UI can
  highlight each one instead of failing on the first — the record is already
  written this way.
* **Credentials are not in the settings file.** Profile secrets live in an OS
  keystore (DPAPI on Windows, libsecret/Secret Service on Linux, Keychain on
  macOS) behind an `ISecretStore`; a plaintext "portable mode" is an explicit
  opt-in, and the diagnostics exporter redacts secrets regardless.
* The connect use case receives an immutable `AppSettings` snapshot, so a
  settings change made in the UI cannot mutate the configuration a running
  tunnel was built from.

## Consequences

**Positive**

* Language and theme changes are immediate, reversible and idempotent, with no
  accumulated styles and no restart.
* View models are unit-testable without a container, a dispatcher or a global,
  because they receive what they need.
* Every user-visible failure is a localized sentence plus a suggested action,
  which is also what makes ADR-0003's "never show a raw Xray error" rule
  enforceable.
* Credentials do not sit in plaintext beside the profiles.

**Negative / costs**

* A JSON localizer plus a markup extension is more machinery than `{x:Static}`
  over generated `.resx`; the payoff is runtime switching and a missing-key test.
* Compiled bindings with a view locator require the View↔ViewModel mapping to be
  registered; an unregistered view model fails at runtime unless a test walks
  every view model type.
* An OS keystore adds a per-platform dependency (and a portable-mode escape
  hatch) compared with one JSON file.
* A single-writer store serialises writes, which is a deliberate throughput
  trade for never producing a half-written settings file.

## Alternatives considered

* **ReactiveUI (the prior art's choice).** Rejected: it is a fine library, but
  the observable pipeline encourages the static/shared-state style this ADR is
  correcting, and the source-generated `[ObservableProperty]` approach produces
  view models that are easier to construct in a test without a scheduler. Note
  explicitly: this is **not** a licence decision — ReactiveUI is MIT.
* **`.resx` + `{x:Static}`.** Rejected: it resolves once per view load, which is
  precisely why the prior art requires a restart to change language.
* **Keep a global `Config` static for convenience.** Rejected: it is the root
  cause of the prior art's untestable view models.
* **Namespace-scoped `Style` objects appended per change.** Rejected: styles
  accumulate and are never removed.
* **Let each view model write the settings file.** Rejected: 20 call sites with
  no single writer is how a settings file gets corrupted.
* **Store credentials in the settings JSON for simplicity.** Rejected: profile
  theft on a shared machine, and the diagnostics exporter would have to redact
  everything.
* **Keep the two-shell (WPF + Avalonia) structure.** Rejected: duplicated XAML
  trees force UI-shaped state into shared view models. One Avalonia tree.

## References

* `docs/research/01-v2rayn-architecture.md` — §1.8 (MVVM framework, no DI
  container, static `_config`, hand-written view locator, theming by appending
  styles, `.resx` + `x:Static` + restart, two settings stores, single-instance
  mutex), §1.9 (the configuration-model quality evidence), §1.10 items 2, 4, 7,
  8, 12, 14 (singleton state, stringly-typed settings, log-text errors, logging
  that cannot be re-enabled, settings-as-code, two XAML trees), §2.7 (the UI /
  MVVM / DI / i18n / settings proposal this ADR adopts), §2.8 (concurrency and
  state), §3.2 T10 (credentials at rest).
* Existing scaffolding: `Directory.Packages.props` (CommunityToolkit.Mvvm,
  Avalonia, Microsoft.Extensions.Hosting),
  `src/MyVpn.UI/MyVpn.UI.csproj` (`AvaloniaUseCompiledBindingsByDefault`,
  embedded `Localization/locales/*.json` and `Assets/**`),
  `src/MyVpn.Core/Settings/AppSettings.cs` (`AppLanguage`, `AppTheme`,
  `UiDensity`, `UiScale`, `AccentColor`, `SchemaVersion`, `Validate`),
  `src/MyVpn.Core/Results/MyVpnError.cs` (`MessageKey`/`Arguments`, and the
  documented rule that the UI never surfaces raw technical text),
  `src/MyVpn.Core/Results/ErrorCodes.cs` (codes are never localized),
  `src/MyVpn.Core/Domain/VpnStateMachine.cs` (the state the UI binds to).
* ADR-0004 (plain `net8.0`, capability probing), ADR-0005 (UI never elevated),
  ADR-0008 (header consent and refusal surfaces), ADR-0011 (honest capability
  reporting in the UI).
