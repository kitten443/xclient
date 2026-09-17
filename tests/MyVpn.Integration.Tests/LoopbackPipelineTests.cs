using System.Diagnostics;
using System.Text.Json.Nodes;
using MyVpn.Application.Connection;
using MyVpn.Core.Domain;
using MyVpn.Core.Results;
using MyVpn.Core.Settings;
using Shouldly;
using Xunit;
using Xunit.Abstractions;

namespace MyVpn.Integration.Tests;

/// <summary>
/// The whole client pipeline, end to end, against loopback-only endpoints.
/// </summary>
/// <remarks>
/// <para>
/// A real Xray server, a real subscription over local HTTP, a real core started by
/// <see cref="VpnSession"/>, and a real request through the local HTTP proxy inbound. No VPN
/// server, no internet access and no privileges are involved — plaintext VLESS is allowed to a
/// private address, which is exactly what makes this possible.
/// </para>
/// <para>
/// The tests are skipped, never failed, when the local core or the geo assets are missing:
/// <c>.tools/</c> is gitignored, so a clean checkout does not have them.
/// </para>
/// <para>
/// <b>Cleanup does not depend on the test runner.</b> Every test holds its fixtures in a
/// <c>finally</c>, and every fixture kills the core process tree when it is disposed. A leaked
/// core holding an inbound port would break every later run of the suite.
/// </para>
/// </remarks>
public sealed class LoopbackPipelineTests
{
    /// <summary>
    /// Address the loopback server binds.
    /// </summary>
    /// <remarks>
    /// Deliberately not <c>127.0.0.1</c>. The check endpoint answers with the peer address it
    /// observes, which for any local caller is <c>127.0.0.1</c>; keeping the server on a different
    /// loopback address is what lets the exit address differ from the server address at all, which
    /// in turn is what makes the client's "the exit address equals the direct address" warning
    /// observable. With the server on <c>127.0.0.1</c> the warning is correctly suppressed,
    /// because then the exit address <i>is</i> the server's own address and reporting it would be
    /// noise.
    /// </remarks>
    private const string ServerAddress = "127.0.0.2";

    private const string CheckEndpointAddress = "127.0.0.1";
    private const string SubscriptionTitle = "Loopback Provider";
    private const string UserId = "11111111-1111-1111-1111-111111111111";

    /// <summary>Bounded budget for a connect attempt: generous for loopback, never unbounded.</summary>
    private static readonly TimeSpan ConnectBudget = TimeSpan.FromSeconds(45);

    /// <summary>Bounded wait for the core's ports to be released after teardown.</summary>
    private static readonly TimeSpan PortReleaseBudget = TimeSpan.FromSeconds(5);

    private readonly ITestOutputHelper _output;

    public LoopbackPipelineTests(ITestOutputHelper output) => _output = output;

    [Fact]
    public async Task The_pipeline_connects_through_a_loopback_server_and_reports_what_it_cannot_prove()
    {
        if (!LoopbackXrayServer.TryLocateCoreBinary(out var binary, out var skipReason))
        {
            _output.WriteLine($"SKIPPED: {skipReason}");
            return;
        }

        if (!LoopbackXrayServer.TryLocateSeedGeoData(out var seedGeoData, out skipReason))
        {
            _output.WriteLine($"SKIPPED: {skipReason}");
            return;
        }

        LoopbackXrayServer? server = null;
        TestGraph? graph = null;

        try
        {
            // ---- a real server, a real subscription, real parsing ---------------
            server = await LoopbackXrayServer.StartAsync(
                binary, ServerAddress, UserId, CancellationToken.None);

            graph = TestGraph.Create(binary, seedGeoData);
            var subscriptionUrl = graph.ServeSubscription(server.ShareLink, SubscriptionTitle);

            var selection = await graph.SelectProfileAsync(subscriptionUrl, graph.PermissiveSubscriptions);
            selection.IsSuccess.ShouldBeTrue(selection.Error?.ToString());

            var profile = selection.Value.Profile;

            // The link survived the trip through HTTP, the header registry and the share-link
            // parser with its address, port and credentials intact.
            profile.Address.ShouldBe(server.ListenAddress);
            profile.Port.ShouldBe(server.Port);
            profile.UserId.ShouldBe(UserId);
            profile.Protocol.ShouldBe(ProxyProtocol.Vless);
            profile.Security.ShouldBe(SecurityKind.None);
            selection.Value.Metadata.Title.ShouldBe(SubscriptionTitle);
            selection.Value.ProfileCount.ShouldBe(1);
            selection.Value.ParseFailureCount.ShouldBe(0);

            // Nothing has been written yet: the config and the geo working copy are created by the
            // connect sequence, which is what makes the post-connect assertions meaningful.
            File.Exists(graph.Paths.ActiveConfigPath).ShouldBeFalse();
            File.Exists(Path.Combine(graph.Paths.GeoDataDirectory, "geoip.dat")).ShouldBeFalse();
            File.Exists(Path.Combine(graph.Paths.GeoDataDirectory, "geosite.dat")).ShouldBeFalse();

            // ---- connect --------------------------------------------------------
            using var budget = new CancellationTokenSource(ConnectBudget);
            var connected = await graph.Session.ConnectAsync(graph.Request(profile), budget.Token);

            // A failed connect must say why: the client core's own output and the server's are the
            // only things that distinguish "the tunnel carried nothing" from "the core never ran".
            connected.IsSuccess.ShouldBeTrue(
                $"connect failed: {connected.Error}{Environment.NewLine}"
                + "---- client core ----"
                + Environment.NewLine
                + string.Join(Environment.NewLine, graph.RecentCoreOutput(40))
                + Environment.NewLine
                + "---- loopback server ----"
                + Environment.NewLine
                + server.Log);

            var snapshot = connected.Value;

            snapshot.State.ShouldBe(VpnConnectionState.Connected);
            snapshot.ProfileId.ShouldBe(profile.Id);
            snapshot.ConnectedAt.ShouldNotBeNull();
            snapshot.CoreProcessId.ShouldNotBeNull();
            IsProcessAlive(snapshot.CoreProcessId!.Value).ShouldBeTrue("the core must be running");
            _output.WriteLine($"connected: pid {snapshot.CoreProcessId}, core {snapshot.CoreVersion}");

            // ---- verification measured real traffic -----------------------------
            var verification = snapshot.Verification;
            verification.ShouldNotBeNull("ConnectAsync must not report Connected without verification");

            verification!.ExitAddress.ShouldBe(graph.EchoAddress);
            verification.Method.ShouldContain(
                $"{CheckEndpointAddress}:{graph.Settings.Proxy.EffectiveHttpPort}");

            // ---- the honest limitation, asserted on purpose ---------------------
            // A `freedom` outbound on a loopback server exits from this same machine, so the
            // address the check endpoint sees through the tunnel is the address it sees without
            // one. The client must therefore refuse to claim the traffic moved:
            // ExitDiffersFromDirect is false and it says so in a warning. This is a feature, not a
            // defect — "the exit address equals the direct address" is the only signal that
            // distinguishes a tunnel from a direct-connection look-alike, and a test that
            // asserted the opposite would be teaching the client to lie.
            verification.DirectAddress.ShouldBe(graph.EchoAddress);
            verification.ExitDiffersFromDirect.ShouldBeFalse(
                "a loopback exit cannot be distinguished from a direct connection; the client must "
                + "not claim that it can");

            snapshot.Warnings.ShouldContain(warning => warning.MessageKey == "error.session.exit_matches_direct");

            var exitMatchesDirect = snapshot.Warnings
                .Single(warning => warning.MessageKey == "error.session.exit_matches_direct");

            exitMatchesDirect.Severity.ShouldBe(ErrorSeverity.Warning);
            exitMatchesDirect.TechnicalDetail!.ShouldContain(verification.ExitAddress);

            // The system proxy was deliberately not wired in (it would reconfigure the desktop),
            // so the session reports that part as unavailable instead of pretending otherwise.
            snapshot.Warnings.ShouldContain(warning => warning.MessageKey == "error.proxy.not_available");

            // ---- the staged config points at the loopback endpoint ---------------
            snapshot.ConfigPath.ShouldBe(graph.Paths.ActiveConfigPath);
            File.Exists(graph.Paths.ActiveConfigPath)
                .ShouldBeTrue($"the generated config must exist at {graph.Paths.ActiveConfigPath}");

            var configText = await File.ReadAllTextAsync(graph.Paths.ActiveConfigPath);
            configText.ShouldContain(server.ListenAddress);

            var config = JsonNode.Parse(configText)!.AsObject();

            var proxyServer = config["outbounds"]!.AsArray()
                .Single(outbound => outbound!["tag"]!.GetValue<string>() == "proxy")!
                ["settings"]!["vnext"]!.AsArray()[0]!.AsObject();

            proxyServer["address"]!.GetValue<string>().ShouldBe(server.ListenAddress);
            proxyServer["port"]!.GetValue<int>().ShouldBe(server.Port);

            // The local inbound ports came from settings, not from a hardcoded default.
            var inbounds = config["inbounds"]!.AsArray().Select(node => node!.AsObject()).ToArray();

            inbounds.ShouldContain(inbound =>
                inbound["protocol"]!.GetValue<string>() == "http"
                && inbound["port"]!.GetValue<int>() == graph.Settings.Proxy.EffectiveHttpPort);

            inbounds.ShouldContain(inbound =>
                inbound["protocol"]!.GetValue<string>() == "socks"
                && inbound["port"]!.GetValue<int>() == graph.Settings.Proxy.ListenPort);

            // ---- the geo working copy was seeded, not merely resolved -----------
            // EnsureWorkingCopyAsync copies the real assets into the writable directory that is
            // exported as XRAY_LOCATION_ASSET, so the directory the core reads is the directory
            // MyVpn validated (the issue #9765 failure mode).
            foreach (var name in new[] { "geoip.dat", "geosite.dat" })
            {
                var seeded = Path.Combine(graph.Paths.GeoDataDirectory, name);
                File.Exists(seeded).ShouldBeTrue($"{name} must be seeded into the working copy");
                new FileInfo(seeded).Length.ShouldBe(new FileInfo(Path.Combine(seedGeoData, name)).Length);
            }

            File.Exists(graph.Paths.GeoManifestPath)
                .ShouldBeTrue("the seeding path records a manifest, so this was not a raw copy");

            snapshot.GeoAvailability.GeoIpAvailable.ShouldBeTrue();
            snapshot.GeoAvailability.GeoSiteAvailable.ShouldBeTrue();

            // ---- disconnect restores the state ----------------------------------
            var disconnected = await graph.Session.DisconnectAsync(CancellationToken.None);
            disconnected.IsSuccess.ShouldBeTrue(disconnected.Error?.ToString());

            graph.Session.State.ShouldBe(VpnConnectionState.Disconnected);
            graph.Session.Snapshot.State.ShouldBe(VpnConnectionState.Disconnected);
            graph.Session.Snapshot.Verification.ShouldBeNull();
            graph.Session.Snapshot.CoreProcessId.ShouldBeNull();

            File.Exists(graph.Paths.ActiveConfigPath)
                .ShouldBeFalse("the staged config must be removed on disconnect");

            IsProcessAlive(snapshot.CoreProcessId!.Value)
                .ShouldBeFalse("the core process from this test must not outlive the disconnect");

            (await LoopbackPort.WaitUntilFreeAsync(
                    CheckEndpointAddress, graph.Settings.Proxy.ListenPort, PortReleaseBudget))
                .ShouldBeTrue("the SOCKS inbound port must be released");

            (await LoopbackPort.WaitUntilFreeAsync(
                    CheckEndpointAddress, graph.Settings.Proxy.EffectiveHttpPort, PortReleaseBudget))
                .ShouldBeTrue("the HTTP inbound port must be released");
        }
        finally
        {
            // Both fixtures kill their processes here, so a failed assertion above can never leave
            // a core holding a port.
            graph?.Dispose();
            server?.Dispose();
        }
    }

    [Fact]
    public async Task A_tunnel_that_cannot_carry_traffic_is_reported_and_rolled_back()
    {
        if (!LoopbackXrayServer.TryLocateCoreBinary(out var binary, out var skipReason))
        {
            _output.WriteLine($"SKIPPED: {skipReason}");
            return;
        }

        // A port nothing is listening on. The profile is syntactically perfect and the core starts
        // happily; the tunnel simply cannot carry anything. This is the rollback path.
        var closedPort = LoopbackPort.Free(CheckEndpointAddress);

        TestGraph? graph = null;

        try
        {
            graph = TestGraph.Create(binary, seedGeoDataDirectory: null);

            var subscriptionUrl = graph.ServeSubscription(
                $"vless://{UserId}@{CheckEndpointAddress}:{closedPort}"
                + "?encryption=none&type=tcp&security=none#Closed%20Port",
                "Closed Port");

            var selection = await graph.SelectProfileAsync(subscriptionUrl, graph.PermissiveSubscriptions);
            selection.IsSuccess.ShouldBeTrue(selection.Error?.ToString());
            selection.Value.Profile.Port.ShouldBe(closedPort);

            using var budget = new CancellationTokenSource(ConnectBudget);
            var connected = await graph.Session.ConnectAsync(graph.Request(selection.Value.Profile), budget.Token);

            // The failure is reported, not hidden, and it names the real reason: the tunnel did not
            // carry the request. Never "success" for a core that merely started.
            connected.IsFailure.ShouldBeTrue(
                "a tunnel to a closed port must not be reported as connected");
            connected.Error!.MessageKey.ShouldBeOneOf(
                "error.session.verification_failed", "diagnostics.warning.server_timeout");
            connected.Error.TechnicalDetail.ShouldNotBeNullOrWhiteSpace();

            _output.WriteLine($"connect failed as reported: {connected.Error}");

            // A first connect that fails returns to Disconnected, not Faulted: Faulted would keep
            // the Kill Switch engaged and fence the machine off over a typo.
            graph.Session.State.ShouldBe(VpnConnectionState.Disconnected);
            graph.Session.Snapshot.State.ShouldBe(VpnConnectionState.Disconnected);
            graph.Session.Snapshot.LastError.ShouldNotBeNull();

            // Nothing is left behind by the rollback.
            File.Exists(graph.Paths.ActiveConfigPath)
                .ShouldBeFalse("a failed connect must not leave a staged config behind");

            if (graph.Session.Snapshot.CoreProcessId is { } startedPid)
            {
                IsProcessAlive(startedPid).ShouldBeFalse("the rolled-back core must not still be running");
            }

            (await LoopbackPort.WaitUntilFreeAsync(
                    CheckEndpointAddress, graph.Settings.Proxy.ListenPort, PortReleaseBudget))
                .ShouldBeTrue("the SOCKS inbound port must be released after rollback");

            (await LoopbackPort.WaitUntilFreeAsync(
                    CheckEndpointAddress, graph.Settings.Proxy.EffectiveHttpPort, PortReleaseBudget))
                .ShouldBeTrue("the HTTP inbound port must be released after rollback");
        }
        finally
        {
            graph?.Dispose();
        }
    }

    [Fact]
    public async Task The_ssrf_guard_refuses_a_loopback_subscription_unless_the_address_policy_is_opted_in()
    {
        // No core is needed: this test is about the fetch path's default policy.
        TestGraph? graph = null;

        try
        {
            graph = TestGraph.Create(coreBinaryPath: null, seedGeoDataDirectory: null);

            var subscriptionUrl = graph.ServeSubscription(
                $"vless://{UserId}@{CheckEndpointAddress}:1"
                + "?encryption=none&type=tcp&security=none#Loopback",
                SubscriptionTitle);

            subscriptionUrl.Host.ShouldBe(CheckEndpointAddress);

            // The default address policy refuses a loopback destination, and it does so with
            // url_invalid rather than url_insecure: plain HTTP was explicitly permitted for this
            // call, so the refusal is the SSRF guard talking and nothing else.
            var refused = await graph.FetchAsync(
                subscriptionUrl,
                graph.PermissiveSubscriptions with { AllowPrivateAddresses = false });

            refused.IsFailure.ShouldBeTrue(
                "a loopback subscription URL must be refused without an explicit opt-in");
            refused.Error!.Code.ShouldBe(ErrorCodes.SubscriptionUrlInvalid);
            refused.Error.MessageKey.ShouldBe("error.subscription.url_invalid");
            refused.Error.TechnicalDetail!.ShouldContain("LoopbackAddress");

            // The identical URL succeeds once the user opts in, which proves the refusal above came
            // from the address policy and not from something else about this URL. The opt-in must
            // be an opt-in: it is what the pipeline tests rely on, and it is never the default.
            var allowed = await graph.FetchAsync(subscriptionUrl, graph.PermissiveSubscriptions);

            allowed.IsSuccess.ShouldBeTrue(allowed.Error?.ToString());
            allowed.Value.Body.ShouldContain("vless://");
            allowed.Value.Headers.ShouldContain(header => header.Key == "profile-title");

            var selected = await graph.SelectProfileAsync(subscriptionUrl, graph.PermissiveSubscriptions);
            selected.IsSuccess.ShouldBeTrue(selected.Error?.ToString());
            selected.Value.Metadata.Title.ShouldBe(SubscriptionTitle);
        }
        finally
        {
            graph?.Dispose();
        }
    }

    /// <summary>True when the process id still refers to a live process.</summary>
    private static bool IsProcessAlive(int processId)
    {
        try
        {
            using var process = Process.GetProcessById(processId);
            return !process.HasExited;
        }
        catch (ArgumentException)
        {
            // No process with that id: exactly what the tests want after teardown.
            return false;
        }
        catch (InvalidOperationException)
        {
            return false;
        }
    }
}
