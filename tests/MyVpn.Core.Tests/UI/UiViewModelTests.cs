using MyVpn.Application.Abstractions;
using MyVpn.Application.Connection;
using MyVpn.Core.Domain;
using MyVpn.Core.Parsing;
using MyVpn.Core.Results;
using MyVpn.Core.Settings;
using MyVpn.Core.Subscriptions;
using MyVpn.UI.Composition;
using MyVpn.UI.Localization;
using MyVpn.UI.ViewModels;
using Shouldly;

namespace MyVpn.Core.Tests.UI;

/// <summary>
/// View-model behaviour: what the window shows, and what it refuses to do.
/// </summary>
/// <remarks>
/// These tests are about the UI's honesty rules rather than about Avalonia. Nothing here builds a
/// window: the view models are plain observable objects, and every claim below is one the user
/// could check on screen.
/// </remarks>
public sealed class UiViewModelTests
{
    private static readonly LocalizationService Localization = new();

    // ---- the connect path is the real session -----------------------------

    [Fact]
    public async Task AConnectedSessionShowsTheVerificationEvidence()
    {
        var session = new FakeVpnSession
        {
            ConnectSnapshot = new()
            {
                State = VpnConnectionState.Connected,
                ProfileName = "Amsterdam",
                CoreVersion = "1.8.24",
                Verification = new ConnectionVerification
                {
                    ExitAddress = "198.51.100.9",
                    DirectAddress = "203.0.113.7",
                    Method = "HTTP proxy",
                    Latency = TimeSpan.FromMilliseconds(143),
                },
            },
        };

        var viewModel = CreateMain(session, null, TestProfiles.Create("Amsterdam"));

        await viewModel.ToggleConnectionCommand.ExecuteAsync(null);

        viewModel.StatusText.ShouldBe(Localization.Get("status.connected"));
        viewModel.CoreVersion.ShouldBe("1.8.24");
        viewModel.ExitAddress.ShouldBe("198.51.100.9");
        viewModel.DirectAddress.ShouldBe("203.0.113.7");
        viewModel.Latency.ShouldBe("143 ms");

        // The exit address differs from the host's own address, so the traffic row says so
        // rather than showing a bare tick.
        viewModel.TrafficMoved.ShouldBe(Localization.Get("status.connected"));
        viewModel.HasError.ShouldBeFalse();
        viewModel.HasWarnings.ShouldBeFalse();
    }

    [Fact]
    public async Task AFailedVerificationIsNeverShownAsConnected()
    {
        var failure = new MyVpnError(
            ErrorCodes.XrayHealthCheckFailed,
            "error.session.verification_failed",
            ErrorSeverity.Error,
            "The tunnel did not carry a request.");

        var session = new FakeVpnSession { ConnectError = failure };
        var viewModel = CreateMain(session, null, TestProfiles.Create());

        await viewModel.ToggleConnectionCommand.ExecuteAsync(null);

        // The session has rolled back to Disconnected and reported the error; the UI must show
        // exactly that and must not fall back to a reassuring state.
        viewModel.StatusText.ShouldBe(Localization.Get("status.disconnected"));
        viewModel.HasError.ShouldBeTrue();
        viewModel.LastError.ShouldContain(Localization.Get("error.session.verification_failed"));
        viewModel.CoreVersion.ShouldBeEmpty();
        viewModel.ExitAddress.ShouldBeEmpty();
        viewModel.IsBusy.ShouldBeFalse();
    }

    [Fact]
    public async Task ASessionWithoutVerificationShowsUnknownRatherThanSuccess()
    {
        var session = new FakeVpnSession();
        var viewModel = CreateMain(session, null, TestProfiles.Create());

        // Connected with verification skipped: the state is real, the evidence is absent.
        session.Publish(new ConnectionSnapshot
        {
            State = VpnConnectionState.Connected,
            ProfileName = "Test server",
        });

        await Task.CompletedTask;

        viewModel.TrafficMoved.ShouldBe(Localization.Get("error.xray.version_unknown"));
        viewModel.ExitAddress.ShouldBeEmpty();
    }

    [Fact]
    public async Task ExitMatchingTheDirectAddressIsReportedAsDegraded()
    {
        var session = new FakeVpnSession();
        var viewModel = CreateMain(session, null, TestProfiles.Create());

        session.Publish(new ConnectionSnapshot
        {
            State = VpnConnectionState.Connected,
            Verification = new ConnectionVerification
            {
                ExitAddress = "203.0.113.7",
                DirectAddress = "203.0.113.7",
                Method = "HTTP proxy",
                Latency = TimeSpan.FromMilliseconds(20),
            },
        });

        await Task.CompletedTask;

        // Equal addresses mean the traffic did not move. Showing the connected state here would
        // be the most misleading thing this screen could do.
        viewModel.TrafficMoved.ShouldBe(Localization.Get("status.degraded"));
    }

    [Fact]
    public async Task ASecondClickDuringAConnectCannotStartASecondOperation()
    {
        var session = new FakeVpnSession { ConnectGate = new TaskCompletionSource() };
        var viewModel = CreateMain(session, null, TestProfiles.Create());

        var first = viewModel.ToggleConnectionCommand.ExecuteAsync(null);

        viewModel.IsBusy.ShouldBeTrue();
        viewModel.ToggleConnectionCommand.CanExecute(null).ShouldBeFalse();

        // The second press is refused by the UI, so it never reaches the session's own gate and
        // the user never sees a spurious "another operation is already running".
        viewModel.ToggleConnectionCommand.CanExecute(null).ShouldBeFalse();
        await viewModel.ToggleConnectionCommand.ExecuteAsync(null);

        session.ConnectRequests.Count.ShouldBe(1);

        session.ConnectGate.SetResult();
        await first;

        viewModel.IsBusy.ShouldBeFalse();
        session.ConnectRequests.Count.ShouldBe(1);
    }

    [Fact]
    public async Task DisconnectIsOfferedWhileTheTunnelIsUpEvenWhenDegraded()
    {
        var session = new FakeVpnSession();
        var viewModel = CreateMain(session, null, TestProfiles.Create());

        session.Publish(new ConnectionSnapshot
        {
            State = VpnConnectionState.Degraded,
            KillSwitchArmed = true,
        });

        viewModel.ConnectButtonText.ShouldBe(Localization.Get("main.disconnect"));
        viewModel.KillSwitchEngaged.ShouldBeTrue();
        viewModel.ToggleConnectionCommand.CanExecute(null).ShouldBeTrue();

        await viewModel.ToggleConnectionCommand.ExecuteAsync(null);

        session.DisconnectCount.ShouldBe(1);
    }

    [Fact]
    public async Task ConnectIsRefusedWhenNoServerIsSelected()
    {
        var session = new FakeVpnSession();
        var viewModel = CreateMain(session, null, profile: null);

        viewModel.CanConnect.ShouldBeFalse();
        viewModel.ToggleConnectionCommand.CanExecute(null).ShouldBeFalse();

        await viewModel.ToggleConnectionCommand.ExecuteAsync(null);

        session.ConnectRequests.ShouldBeEmpty();
        viewModel.ServerName.ShouldBe(Localization.Get("main.no_server"));
    }

    [Fact]
    public async Task WarningsFromTheSessionAreShownLocalized()
    {
        var session = new FakeVpnSession
        {
            ConnectSnapshot = new ConnectionSnapshot
            {
                State = VpnConnectionState.Connected,
                Warnings = new[]
                {
                    new MyVpnError(
                        ErrorCodes.KillSwitchApplyFailed,
                        "error.killswitch.needs_privileges",
                        ErrorSeverity.Warning),
                },
            },
        };

        var viewModel = CreateMain(session, null, TestProfiles.Create());

        await viewModel.ToggleConnectionCommand.ExecuteAsync(null);

        viewModel.HasWarnings.ShouldBeTrue();
        viewModel.Warnings.Count.ShouldBe(1);
        viewModel.Warnings[0].Value.ShouldBe(Localization.Get("error.killswitch.needs_privileges"));
    }

    // ---- subscription import: the three gates -----------------------------

    [Fact]
    public async Task AnImportAppliesNothingUntilTheUserConsents()
    {
        var store = new FakeUserSettingsStore();
        var importer = new FakeSubscriptionImporter { Next = ImportWithPendingChanges() };
        var viewModel = CreateImport(importer, store);

        viewModel.Url = "https://provider.example/sub?token=SECRET";
        await viewModel.ImportAsync();

        // Gate A is applied; the profile count is visible.
        viewModel.ProviderTitle.ShouldBe("Provider");
        viewModel.ProfileCount.ShouldBe(1);

        // Gate B is staged, not applied: the store's settings are untouched.
        viewModel.HasPendingChanges.ShouldBeTrue();
        store.Settings.TunnelMode.ShouldBe(new AppSettings().TunnelMode);
        store.SaveCount.ShouldBe(0);
    }

    [Fact]
    public async Task ConsentingAppliesOnlyTheMappedChange()
    {
        var store = new FakeUserSettingsStore();
        var importer = new FakeSubscriptionImporter { Next = ImportWithPendingChanges() };
        var viewModel = CreateImport(importer, store);

        SubscriptionConsentEventArgs? consented = null;
        viewModel.ConsentGiven += (_, e) => consented = e;

        viewModel.Url = "https://provider.example/sub?token=SECRET";
        await viewModel.ImportAsync();
        viewModel.ApplyConsentedChangesCommand.Execute(null);

        consented.ShouldNotBeNull();

        // The TUN toggle was consented to, so the proposed snapshot has it; nothing else moved.
        consented!.ProposedSettings.TunnelMode.ShouldBe(TunnelMode.Tun);
        consented.ProposedSettings.KillSwitch.ShouldBe(store.Settings.KillSwitch);
        consented.Result.Profiles.Count.ShouldBe(1);
    }

    [Fact]
    public async Task AConsentTokenThatDoesNotMatchTheValueIsRefused()
    {
        var store = new FakeUserSettingsStore();
        var importer = new FakeSubscriptionImporter
        {
            Next = ImportWithPendingChanges() with
            {
                // A provider that obtained consent for one value and then changed it.
                PendingChanges = new[]
                {
                    PendingChangeFor("tun-enable", "true") with { ConsentToken = "deadbeef" },
                },
            },
        };

        var viewModel = CreateImport(importer, store);
        SubscriptionConsentEventArgs? consented = null;
        viewModel.ConsentGiven += (_, e) => consented = e;

        viewModel.Url = "https://provider.example/sub";
        await viewModel.ImportAsync();
        viewModel.ApplyConsentedChangesCommand.Execute(null);

        // The gate is a binding, not a formality: a mismatched token applies nothing.
        viewModel.PendingChanges[0].Outcome.ShouldBe(Localization.Get("error.header.gate_violation"));
        consented.ShouldNotBeNull();
        consented!.ProposedSettings.TunnelMode.ShouldBe(store.Settings.TunnelMode);
    }

    [Fact]
    public async Task RefusedHeadersAreShownAsANoticeAndNeverOffered()
    {
        var store = new FakeUserSettingsStore();
        var importer = new FakeSubscriptionImporter
        {
            Next = ImportWithPendingChanges() with { RefusedHeaders = new[] { "custom-tunnel-config", "routing" } },
        };

        var viewModel = CreateImport(importer, store);
        viewModel.Url = "https://provider.example/sub";

        await viewModel.ImportAsync();

        viewModel.HasRefusedHeaders.ShouldBeTrue();
        viewModel.RefusedNotice.ShouldContain("custom-tunnel-config");
        viewModel.RefusedNotice.ShouldContain("routing");

        // Not applied and not applicable: a refused header must not appear among the changes the
        // user can consent to, because "accept this arbitrary routing config" is not a choice.
        viewModel.PendingChanges.ShouldNotContain(row => row.HeaderName == "custom-tunnel-config");
        viewModel.PendingChanges.ShouldNotContain(row => row.HeaderName == "routing");
    }

    [Fact]
    public void TheSubscriptionUrlIsOnlyEverShownMasked()
    {
        const string url = "https://provider.example/sub/9f8e7d6c5b4a?token=SUPERSECRET";
        var store = new FakeUserSettingsStore();
        var viewModel = CreateImport(new FakeSubscriptionImporter(), store);

        viewModel.Restore(url);

        viewModel.MaskedUrlHint.ShouldBe("https://provider.example/…");
        viewModel.MaskedUrlHint.ShouldNotContain("SUPERSECRET");
        viewModel.MaskedUrlHint.ShouldNotContain("9f8e7d6c5b4a");
        viewModel.MaskedUrlHint.ShouldNotContain("token");

        // The raw value exists only in the input field the user typed it into, so masking it is
        // what keeps it off screenshots and out of bug reports.
        viewModel.Url.ShouldBe(url);
    }

    [Fact]
    public async Task AnAcceptedImportPersistsTheProfilesAndStaysReadyToConnect()
    {
        var store = new FakeUserSettingsStore();
        var importer = new FakeSubscriptionImporter { Next = ImportWithPendingChanges() };

        var session = new FakeVpnSession();
        var viewModel = CreateMain(session, store, profile: null);

        // The window shares the import view model the app composed, so the consent path under
        // test is the one the user's button drives.
        viewModel.Subscription.Present(ImportWithPendingChanges());
        viewModel.Subscription.ApplyConsentedChangesCommand.Execute(null);

        // The handler behind ConsentGiven persists asynchronously; let it finish.
        await WaitForAsync(() => store.SaveCount > 0).ConfigureAwait(true);

        store.Profiles.Count.ShouldBe(1);
        store.SubscriptionUrl.ShouldBe("https://provider.example/sub?token=SECRET");
        store.Settings.TunnelMode.ShouldBe(TunnelMode.Tun);
        store.Settings.SelectedProfileId.ShouldBe(store.Profiles[0].Id);

        // The consent path must leave a connectable state, not an empty list.
        viewModel.CanConnect.ShouldBeTrue();
        viewModel.SelectedProfile.ShouldNotBeNull();
        viewModel.SelectedProfile!.Profile.Id.ShouldBe(store.Profiles[0].Id);
    }

    [Fact]
    public void MaskingKeepsANonDefaultPort()
    {
        SubscriptionImportViewModel
            .MaskUrl("https://provider.example:8443/sub/TOKEN", Localization)
            .ShouldBe("https://provider.example:8443/…");
    }

    [Fact]
    public void AMalformedUrlIsNotEchoedBack()
    {
        SubscriptionImportViewModel
            .MaskUrl("not a url SENSITIVE", Localization)
            .ShouldBe(Localization.Get("error.xray.version_unknown"));
    }

    [Fact]
    public void TheConsentTokenImplementationMatchesTheCoreRule()
    {
        // The UI cannot see the core's internal ConsentToken helper, so it mirrors it. This pins
        // the mirror: (subscription, header, value) bound to one opaque token.
        const string subscriptionId = "https://provider.example/sub";
        const string headerName = "tun-enable";
        const string fingerprint = "abc123";

        var expected = Convert.ToHexString(
                System.Security.Cryptography.SHA256.HashData(
                    System.Text.Encoding.UTF8.GetBytes(
                        $"{subscriptionId}\n{headerName}\nabc123")))
            .ToLowerInvariant();

        PendingChangeApplier.ConsentToken(subscriptionId, headerName, fingerprint)
            .ShouldBe(expected);
    }

    [Fact]
    public void AnUnmappedHeaderIsReportedRatherThanGuessed()
    {
        var settings = new AppSettings();

        // "fallback-url" is genuinely confirmation-gated in the catalog and genuinely has no
        // field in this client. Writing it somewhere plausible would be worse than saying so.
        var outcome = PendingChangeApplier.Apply(
            ref settings,
            PendingChangeFor("fallback-url", "https://other.example/sub"));

        outcome.ShouldBe(PendingChangeApplier.Outcome.Unsupported);

        // Nothing moved. Compared field by field rather than with record equality, because the
        // settings tree holds collections and a record comparison would be comparing references.
        settings.TunnelMode.ShouldBe(new AppSettings().TunnelMode);
        settings.Mux.Enabled.ShouldBeFalse();
        settings.Routing.BlockAds.ShouldBeFalse();
        settings.Connectivity.BindToPhysicalInterface.ShouldBeTrue();
        settings.Subscriptions.AutoUpdate.ShouldBeTrue();
    }

    [Fact]
    public void AMappedHeaderWritesTheFieldItNames()
    {
        var settings = new AppSettings();

        var outcome = PendingChangeApplier.Apply(ref settings, PendingChangeFor("mux-enable", "true"));

        outcome.ShouldBe(PendingChangeApplier.Outcome.Applied);
        settings.Mux.Enabled.ShouldBeTrue();
    }

    // ---- diagnostics ------------------------------------------------------

    [Fact]
    public void EveryDiagnosticOutcomeIsRenderedFromItsKey()
    {
        var store = new FakeUserSettingsStore();
        var viewModel = CreateDiagnostics(store);

        viewModel.Render(new Core.Diagnostics.DiagnosticReport
        {
            GeneratedAt = DateTimeOffset.UtcNow,
            TotalDuration = TimeSpan.FromMilliseconds(1200),
            Checks = new[]
            {
                new Core.Diagnostics.DiagnosticCheckResult
                {
                    Id = "core",
                    TitleKey = "diagnostics.check.core_binary",
                    Status = Core.Diagnostics.DiagnosticStatus.Success,
                    MessageKey = "diagnostics.result.ok",
                    TechnicalDetail = "/usr/bin/xray",
                    Duration = TimeSpan.FromMilliseconds(12),
                },
                new Core.Diagnostics.DiagnosticCheckResult
                {
                    Id = "geodata",
                    TitleKey = "diagnostics.check.geodata",
                    Status = Core.Diagnostics.DiagnosticStatus.Error,
                    MessageKey = "error.geodata.missing",
                    RemediationKey = "geodata.repair",
                    Args = new Dictionary<string, string>(StringComparer.Ordinal) { ["asset"] = "geoip.dat" },
                },
                new Core.Diagnostics.DiagnosticCheckResult
                {
                    Id = "tun",
                    TitleKey = "diagnostics.check.tun_interface",
                    Status = Core.Diagnostics.DiagnosticStatus.Skipped,
                    MessageKey = "diagnostics.skip.tun_not_selected",
                },
            },
        });

        viewModel.Checks.Count.ShouldBe(3);
        viewModel.Checks[0].Title.ShouldBe(Localization.Get("diagnostics.check.core_binary"));
        viewModel.Checks[0].Message.ShouldBe(Localization.Get("diagnostics.result.ok"));
        viewModel.Checks[0].TechnicalDetail.ShouldBe("/usr/bin/xray");

        viewModel.Checks[1].IsProblem.ShouldBeTrue();
        viewModel.Checks[1].Message.ShouldBe(Localization.Get("error.geodata.missing"));
        viewModel.Checks[1].Remediation.ShouldBe(Localization.Get("geodata.repair"));

        viewModel.Checks[2].IsSuccess.ShouldBeFalse();
        viewModel.Checks[2].IsProblem.ShouldBeFalse();

        // Counts, not a hand-built English sentence: e=1 w=0 n=3.
        viewModel.Summary.ShouldContain("e=1");
        viewModel.Summary.ShouldContain("n=3");
    }

    // ---- persistence ------------------------------------------------------

    [Fact]
    public async Task TheRealStoreRoundTripsStateToADiscFile()
    {
        var root = Path.Combine(Path.GetTempPath(), "myvpn-ui-store-tests", Guid.NewGuid().ToString("N"));

        try
        {
            var paths = new Infrastructure.App.AppPaths(root);
            paths.EnsureCreated();

            var real = new JsonUserSettingsStore(
                paths,
                new Infrastructure.App.AtomicConfigFileStore(),
                Microsoft.Extensions.Logging.Abstractions.NullLogger<JsonUserSettingsStore>.Instance);

            var profile = TestProfiles.Create("Amsterdam");

            real.Settings = new AppSettings { TunnelMode = TunnelMode.SystemProxy };
            real.Profiles = new[] { profile };
            real.SubscriptionUrl = "https://provider.example/sub/TOKEN";
            real.CoreBinaryPath = "/usr/bin/xray";
            real.MarkDirty();

            await real.SaveAsync(CancellationToken.None);
            real.IsDirty.ShouldBeFalse();

            // A fresh instance, so the values can only come from the file.
            var reloaded = new JsonUserSettingsStore(
                paths,
                new Infrastructure.App.AtomicConfigFileStore(),
                Microsoft.Extensions.Logging.Abstractions.NullLogger<JsonUserSettingsStore>.Instance);

            var state = await reloaded.LoadAsync(CancellationToken.None);

            state.Settings.TunnelMode.ShouldBe(TunnelMode.SystemProxy);
            state.Profiles.Count.ShouldBe(1);
            state.Profiles[0].Id.ShouldBe(profile.Id);
            state.SubscriptionUrl.ShouldBe("https://provider.example/sub/TOKEN");
            state.CoreBinaryPath.ShouldBe("/usr/bin/xray");
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    [Fact]
    public async Task ACorruptStateFileFallsBackToDefaultsInsteadOfFailing()
    {
        var root = Path.Combine(Path.GetTempPath(), "myvpn-ui-store-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);

        try
        {
            await File.WriteAllTextAsync(
                Path.Combine(root, "ui-state.json"),
                "{ this is not json").ConfigureAwait(true);

            var store = new JsonUserSettingsStore(
                new Infrastructure.App.AppPaths(root),
                new Infrastructure.App.AtomicConfigFileStore(),
                Microsoft.Extensions.Logging.Abstractions.NullLogger<JsonUserSettingsStore>.Instance);

            var state = await store.LoadAsync(CancellationToken.None);

            // The app still starts. A corrupt file is a warning, not a reason to refuse to run.
            state.Settings.TunnelMode.ShouldBe(new AppSettings().TunnelMode);
            state.Profiles.ShouldBeEmpty();
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    // ---- helpers ----------------------------------------------------------

    /// <summary>
    /// Waits for a condition driven by an event handler, so a test never sleeps a fixed amount.
    /// </summary>
    private static async Task WaitForAsync(Func<bool> condition)
    {
        for (var attempt = 0; attempt < 200 && !condition(); attempt++)
        {
            await Task.Delay(5).ConfigureAwait(true);
        }

        condition().ShouldBeTrue("the asynchronous handler did not complete in time");
    }

    private static MainWindowViewModel CreateMain(
        FakeVpnSession session,
        FakeUserSettingsStore? store,
        ServerProfile? profile)
    {
        store ??= new FakeUserSettingsStore();
        store.Settings = store.Settings with { AdvancedMode = false };
        store.Profiles = profile is null ? Array.Empty<ServerProfile>() : new[] { profile };

        var servers = new ServerListViewModel(Localization);
        var subscription = new SubscriptionImportViewModel(
            new FakeSubscriptionImporter(),
            store,
            Localization);

        var diagnostics = new DiagnosticsViewModel(
            new Infrastructure.Diagnostics.DiagnosticRunner(
                Infrastructure.Diagnostics.DiagnosticRunner.CreateDefaultChecks(),
                Microsoft.Extensions.Logging.Abstractions.NullLogger<Infrastructure.Diagnostics.DiagnosticRunner>.Instance),
            Localization,
            BuildContextProvider(store, servers));

        var settings = new SettingsViewModel(Localization, store);

        var viewModel = new MainWindowViewModel(
            session,
            store,
            Localization,
            servers,
            subscription,
            diagnostics,
            settings);

        // InitializeAsync is what the app runs at startup; the tests need the profile list the
        // same way the window does.
        viewModel.InitializeAsync().GetAwaiter().GetResult();
        return viewModel;
    }

    private static SubscriptionImportViewModel CreateImport(
        FakeSubscriptionImporter importer,
        FakeUserSettingsStore store) =>
        new(importer, store, Localization);

    private static DiagnosticsViewModel CreateDiagnostics(FakeUserSettingsStore store) =>
        new(
            new Infrastructure.Diagnostics.DiagnosticRunner(
                Infrastructure.Diagnostics.DiagnosticRunner.CreateDefaultChecks(),
                Microsoft.Extensions.Logging.Abstractions.NullLogger<Infrastructure.Diagnostics.DiagnosticRunner>.Instance),
            Localization,
            BuildContextProvider(store, new ServerListViewModel(Localization)));

    private static DiagnosticContextProvider BuildContextProvider(
        FakeUserSettingsStore store,
        ServerListViewModel servers)
    {
        var root = Path.Combine(Path.GetTempPath(), "myvpn-ui-vm-tests", Guid.NewGuid().ToString("N"));

        return new DiagnosticContextProvider(
            store,
            servers,
            new Infrastructure.Geo.GeoDataManager(
                new Infrastructure.Geo.GeoDataOptions
                {
                    AssetDirectory = Path.Combine(root, "assets"),
                    BackupDirectory = Path.Combine(root, "backup"),
                    ManifestPath = Path.Combine(root, "manifest.json"),
                },
                Microsoft.Extensions.Logging.Abstractions.NullLogger<Infrastructure.Geo.GeoDataManager>.Instance),
            new Infrastructure.Xray.XrayEngineManager(
                Microsoft.Extensions.Logging.Abstractions.NullLogger<Infrastructure.Xray.XrayEngineManager>.Instance,
                new Infrastructure.Xray.XrayEngineOptions { AutoRestart = false }));
    }

    private static SubscriptionImportResult ImportWithPendingChanges() => new()
    {
        SubscriptionUrl = "https://provider.example/sub?token=SECRET",
        Title = "Provider",
        Announce = "Welcome",
        Profiles = new[] { TestProfiles.Create("Amsterdam") },
        Failures = Array.Empty<ShareLinkFailure>(),
        RefusedHeaders = Array.Empty<string>(),
        PendingChanges = new[] { PendingChangeFor("tun-enable", "true") },
        Errors = Array.Empty<MyVpnError>(),
    };

    private static PendingChange PendingChangeFor(string header, string value) => new()
    {
        Id = header,
        HeaderName = header,
        Value = value,
        ValueFingerprint = "fingerprint",
        Risk = ChangeRisk.High,
        LabelKey = "header.tun_enable",
        ConsentToken = PendingChangeApplier.ConsentToken(
            "https://provider.example/sub?token=SECRET",
            header,
            "fingerprint"),
    };
}
