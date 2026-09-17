using System.Diagnostics;
using System.Globalization;
using MyVpn.Application.Connection;
using MyVpn.Core.Domain;
using MyVpn.Core.Settings;
using MyVpn.Platform.Linux.Tun;

namespace MyVpn.Rootless.Harness;

/// <summary>
/// Runs the whole scenario inside the throwaway client namespace.
/// </summary>
/// <remarks>
/// <para>
/// <b>Nothing here can touch the host's network.</b> The helper process is started by the test as
/// <c>unshare -rmn --propagation private</c>, so it is root inside a fresh user namespace and owns a
/// fresh network namespace with a fresh routing table, a fresh nftables ruleset and no interfaces
/// other than the ones it creates. Every address, route, device and firewall rule below therefore
/// exists only for the lifetime of this process tree. That is what makes these assertions safe to
/// run anywhere — including on a machine whose own network must not be disturbed — and it is why
/// no assertion here needs to be hedged about the host's state.
/// </para>
/// <para>
/// The mount namespace is taken as well, and made private, for one specific reason: the DNS
/// executor probes <c>resolvectl</c>, and a shared <c>/run/dbus/system_bus_socket</c> would let it
/// reach the <i>host's</i> systemd-resolved with this namespace's interface index — an index that
/// means something completely different on the host. Hiding the socket makes that impossible and
/// leaves the executor on its documented file backend.
/// </para>
/// </remarks>
internal static class ClientScenario
{
    /// <summary>Address of this namespace's uplink end.</summary>
    public const string ClientAddress = "10.0.0.2";

    /// <summary>Name of the uplink interface in this namespace.</summary>
    public const string UplinkInterface = "cli0";

    /// <summary>Peer name the client creates and hands to the far side.</summary>
    public const string PeerInterface = "srv0";

    /// <summary>Name the core gives the tunnel interface (the builder's default).</summary>
    public const string TunInterface = "myvpn0";

    /// <summary>Address the tunnel interface is expected to carry (the TUN inbound's gateway).</summary>
    public const string ExpectedTunAddress = "172.19.0.1/30";

    /// <summary>The resolver the namespace "already had", in the TEST-NET-2 documentation range.</summary>
    public const string PreexistingResolver = "198.51.100.53";

    private static readonly TimeSpan IpTimeout = TimeSpan.FromSeconds(10);

    public static async Task<RootlessReport> RunAsync(HarnessArgs arguments, CancellationToken cancellationToken)
    {
        var work = arguments.Work;
        var report = new RootlessReport { KillSwitchMode = arguments.KillSwitch };
        var resolvConfPath = Path.Combine(work, "resolv.conf");
        var readyPath = Path.Combine(work, "server-ready");
        var errorPath = Path.Combine(work, "server-error");
        var stopPath = Path.Combine(work, "server-stop");

        Process? farSide = null;
        VpnComposition? composition = null;
        var connected = false;

        var options = new ScenarioOptions
        {
            WorkDirectory = work,
            AppRoot = Path.Combine(work, "app"),
            CoreBinaryPath = arguments.Xray,
            ResolvConfPath = resolvConfPath,
            DnsStateDirectory = Path.Combine(work, "dns-state"),
            SeedGeoDataDirectory = Path.GetDirectoryName(arguments.Xray) ?? work,
            KillSwitch = arguments.KillSwitch == "on-demand" ? KillSwitchMode.OnDemand : KillSwitchMode.Disabled,
            ServerAddress = ServerRole.UplinkAddress,
            ServerPort = arguments.ServerPort,
            UserId = arguments.UserId,
        };

        try
        {
            // ---- the DNS sandbox -------------------------------------------------
            report.Client.DbusSocketHidden = HideSystemBus(report);

            // Fail closed on the host's resolver. `resolvectl` reaches systemd-resolved over a
            // socket that is shared with every namespace on the machine, so if it still answers,
            // the executor could apply this namespace's interface index to a host interface. The
            // run stops here instead: a test is never worth changing the machine it runs on.
            if (!report.Client.DbusSocketHidden && ResolvectlAnswers())
            {
                report.Client.DnsIsolationFailed = true;
                report.Failure = "the host's systemd-resolved is reachable from inside the namespace "
                    + "(the D-Bus socket could not be hidden), so the DNS executor could modify the "
                    + "host's resolver. Refusing to run.";
                return report;
            }

            await File.WriteAllTextAsync(
                resolvConfPath, $"nameserver {PreexistingResolver}\n", cancellationToken).ConfigureAwait(false);
            report.Client.ResolvConfBeforeConnect = KernelState.ReadFileOrEmpty(resolvConfPath);
            Trace(report, $"resolv.conf before  : {OneLine(report.Client.ResolvConfBeforeConnect)}");

            // ---- the client's "physical" uplink ----------------------------------
            await IpAsync(report, "link", "set", "lo", "up").ConfigureAwait(false);

            farSide = StartFarSide(arguments, work);

            await IpAsync(report, "link", "add", PeerInterface, "type", "veth", "peer", "name", UplinkInterface)
                .ConfigureAwait(false);
            await IpAsync(report, "link", "set", PeerInterface, "netns", farSide.Id.ToString(CultureInfo.InvariantCulture))
                .ConfigureAwait(false);

            await IpAsync(report, "addr", "add", $"{ClientAddress}/32", "dev", UplinkInterface).ConfigureAwait(false);
            await IpAsync(report, "link", "set", UplinkInterface, "up").ConfigureAwait(false);
            await IpAsync(report, "route", "add", $"{ServerRole.UplinkAddress}/32", "dev", UplinkInterface)
                .ConfigureAwait(false);

            // The uplink default carries the metric a DHCP client or NetworkManager would give it
            // (100), not 0. That is not a convenience: route selection is metric-first, so a
            // metric-0 uplink default outranks the tunnel's metric-1 default and IPv4 traffic keeps
            // using the uplink. MyVpn's plan adds a route rather than deleting the physical one, so
            // the tunnel wins exactly when the physical default has the worse metric — the normal
            // case on a managed desktop, and the case exercised here.
            await IpAsync(report, "route", "add", "default", "via", ServerRole.UplinkAddress, "dev", UplinkInterface,
                "metric", "100").ConfigureAwait(false);

            await WaitForAsync(() => File.Exists(readyPath), TimeSpan.FromSeconds(40), cancellationToken)
                .ConfigureAwait(false);

            if (!File.Exists(readyPath))
            {
                report.Failure = "the far side never became ready: "
                    + FailDetail(errorPath, Path.Combine(work, "server-core.log"), farSide);
                return report;
            }

            report.Client.InterfacesBeforeConnect = await KernelState.InterfaceNamesAsync().ConfigureAwait(false);
            report.Client.UplinkDefaultRoute = await KernelState.DefaultRouteAsync().ConfigureAwait(false);
            report.Client.RouteToTargetBeforeConnect =
                await KernelState.RouteGetAsync(ServerRole.TargetAddress).ConfigureAwait(false);

            Trace(report, $"interfaces before   : {string.Join(", ", report.Client.InterfacesBeforeConnect)}");
            Trace(report, $"default route before: {OneLine(report.Client.UplinkDefaultRoute)}");
            Trace(report, $"route to target     : {OneLine(report.Client.RouteToTargetBeforeConnect)}");

            // Negative control: the target is reachable *without* the tunnel, and the source address
            // it observes is this namespace's uplink address. Without this, a successful request
            // after the connect would prove nothing about which path it took.
            var direct = await HttpProbe.GetAsync(
                ServerRole.TargetAddress, ServerRole.TargetPort, TimeSpan.FromSeconds(6), cancellationToken)
                .ConfigureAwait(false);

            report.Client.DirectRequestStatus = direct.Status;
            report.Client.DirectRequestBody = direct.Body;
            report.Client.DirectRequestFirstByteMilliseconds = direct.FirstByteMilliseconds;
            Trace(report, $"direct request      : {direct}");

            // ---- the real composition, wired as the CLI wires it -----------------
            var loggers = new RecordingLoggerFactory();
            composition = MyVpnComposition.Create(options, loggers);

            var connectedResult = await composition.Session.ConnectAsync(
                new ConnectRequest
                {
                    Profile = MyVpnComposition.BuildProfile(options),
                    Settings = MyVpnComposition.BuildSettings(options.KillSwitch),
                    CoreBinaryPath = arguments.Xray,

                    // The built-in verification reaches a public endpoint to compare exit addresses,
                    // and this namespace has no route off the machine. The traffic probe below
                    // replaces it and is stricter: it shows *where* the request came out.
                    SkipVerification = true,
                },
                cancellationToken).ConfigureAwait(false);

            report.Client.ConnectSucceeded = connectedResult.IsSuccess;

            if (!connectedResult.IsSuccess)
            {
                report.Client.ConnectError = connectedResult.Error?.ToString();

                foreach (var line in composition.Engine.GetRecentOutput(20))
                {
                    report.Client.ConnectWarnings.Add($"core: {line}");
                }

                Trace(report, $"CONNECT FAILED      : {report.Client.ConnectError}");
                return report;
            }

            connected = true;
            report.Client.CoreProcessId = connectedResult.Value.CoreProcessId ?? 0;

            foreach (var warning in connectedResult.Value.Warnings)
            {
                report.Client.ConnectWarnings.Add(
                    $"{warning.Severity} {warning.Code}: {warning.MessageKey} — {warning.TechnicalDetail}");
            }

            Trace(report, $"connected           : core pid {report.Client.CoreProcessId}, "
                + $"{connectedResult.Value.Warnings.Count} warning(s)");

            foreach (var warning in report.Client.ConnectWarnings)
            {
                Trace(report, $"warning             : {warning}");
            }

            // ---- while connected -------------------------------------------------
            var tun = new LinuxTunDeviceManager();
            report.Client.TunInterfaceName = TunInterface;
            report.Client.TunExistsWhileConnected =
                await tun.ExistsAsync(TunInterface, cancellationToken).ConfigureAwait(false);
            report.Client.TunAddresses =
                (await tun.GetAddressesAsync(TunInterface, cancellationToken).ConfigureAwait(false)).ToList();

            report.Client.DefaultRouteWhileConnected = await KernelState.DefaultRouteAsync().ConfigureAwait(false);
            report.Client.RouteToServerWhileConnected =
                await KernelState.RouteGetAsync(ServerRole.UplinkAddress).ConfigureAwait(false);
            report.Client.RouteToTargetWhileConnected =
                await KernelState.RouteGetAsync(ServerRole.TargetAddress).ConfigureAwait(false);
            report.Client.ResolvConfWhileConnected = KernelState.ReadFileOrEmpty(resolvConfPath);
            report.Client.DnsBackendName = composition.Dns.BackendName;
            report.Client.DnsRecordedPreviousServers = composition.Dns.RecordedPreviousServers.ToList();
            report.Client.NftTableWhileConnected = await KernelState.NftKillSwitchTableAsync().ConfigureAwait(false);

            Trace(report, $"tun exists          : {report.Client.TunExistsWhileConnected} "
                + $"[{string.Join(", ", report.Client.TunAddresses)}]");
            Trace(report, $"default route       : {OneLine(report.Client.DefaultRouteWhileConnected)}");
            Trace(report, $"route to server     : {OneLine(report.Client.RouteToServerWhileConnected)}");
            Trace(report, $"route to target     : {OneLine(report.Client.RouteToTargetWhileConnected)}");
            Trace(report, $"dns backend         : {report.Client.DnsBackendName}, "
                + $"previous recorded: {string.Join(", ", report.Client.DnsRecordedPreviousServers)}");
            Trace(report, $"resolv.conf         : {OneLine(report.Client.ResolvConfWhileConnected)}");
            Trace(report, $"nft table           : {NftSummary(report.Client.NftTableWhileConnected)}");

            var tunnelled = await HttpProbe.GetAsync(
                ServerRole.TargetAddress, ServerRole.TargetPort, TimeSpan.FromSeconds(20), cancellationToken)
                .ConfigureAwait(false);

            report.Client.TunnelRequestStatus = tunnelled.Status;
            report.Client.TunnelRequestBody = tunnelled.Body;
            report.Client.TunnelRequestMilliseconds = tunnelled.Milliseconds;
            report.Client.TunnelRequestFirstByteMilliseconds = tunnelled.FirstByteMilliseconds;
            report.Client.CoreLogTail = composition.Engine.GetRecentOutput(40).ToList();
            Trace(report, $"request via tunnel  : {tunnelled}");

            // ---- disconnect ------------------------------------------------------
            var disconnected = await composition.Session.DisconnectAsync(cancellationToken).ConfigureAwait(false);
            connected = false;
            report.Client.DisconnectSucceeded = disconnected.IsSuccess;
            report.Client.DisconnectError = disconnected.Error?.ToString();
            Trace(report, $"disconnected        : {disconnected.IsSuccess} {report.Client.DisconnectError}".TrimEnd());

            // ---- after the disconnect -------------------------------------------
            report.Client.TunExistsAfterDisconnect =
                await tun.ExistsAsync(TunInterface, cancellationToken).ConfigureAwait(false);
            report.Client.DefaultRouteAfterDisconnect = await KernelState.DefaultRouteAsync().ConfigureAwait(false);
            report.Client.RouteToTargetAfterDisconnect =
                await KernelState.RouteGetAsync(ServerRole.TargetAddress).ConfigureAwait(false);
            report.Client.RouteToServerAfterDisconnect =
                await KernelState.RouteGetAsync(ServerRole.UplinkAddress).ConfigureAwait(false);
            report.Client.ResolvConfAfterDisconnect = KernelState.ReadFileOrEmpty(resolvConfPath);
            report.Client.NftTableAfterDisconnect = await KernelState.NftKillSwitchTableAsync().ConfigureAwait(false);
            report.Client.InterfacesAfterDisconnect = await KernelState.InterfaceNamesAsync().ConfigureAwait(false);
            report.Client.CoreProcessesInNamespaceAfterDisconnect =
                KernelState.CountProcessesInOurNamespaceRunning(arguments.Xray);

            Trace(report, $"default route after : {OneLine(report.Client.DefaultRouteAfterDisconnect)}");
            Trace(report, $"route to target     : {OneLine(report.Client.RouteToTargetAfterDisconnect)}");
            Trace(report, $"resolv.conf after   : {OneLine(report.Client.ResolvConfAfterDisconnect)}");
            Trace(report, $"nft table after     : {NftSummary(report.Client.NftTableAfterDisconnect)}");
            Trace(report, $"interfaces after    : {string.Join(", ", report.Client.InterfacesAfterDisconnect)}");
            Trace(report, $"core procs in ns    : {report.Client.CoreProcessesInNamespaceAfterDisconnect}");

            report.Completed = true;
            return report;
        }
        catch (Exception ex)
        {
            report.Failure = ex.ToString();
            return report;
        }
        finally
        {
            // The report is returned after this block runs, so the far-side evidence is collected
            // here: it is worth having even when the flow above threw.
            report.Server.Addresses = ReadLines(Path.Combine(work, "server-addresses.txt"));
            report.Server.ServedRequests = ReadLines(Path.Combine(work, "target-requests.log"));
            report.Server.CoreLogTail = TailOf(Path.Combine(work, "server-core.log"), 10);

            if (composition is not null && connected)
            {
                try
                {
                    await composition.Session.DisconnectAsync(CancellationToken.None).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    report.Trace.Add($"teardown: disconnect threw {ex.GetType().Name}: {ex.Message}");
                }
            }

            // The far side is a child of this process and holds its own namespace alive. It is
            // stopped here rather than left to the parent, so a failure earlier in the flow cannot
            // leave a namespace — and a second core process — behind.
            if (farSide is not null)
            {
                try
                {
                    await File.WriteAllTextAsync(stopPath, "stop", CancellationToken.None).ConfigureAwait(false);
                }
                catch (IOException)
                {
                    // The kill below is the real teardown.
                }

                try
                {
                    if (!farSide.WaitForExit(2000))
                    {
                        CommandRunner.TryKill(farSide);
                    }
                }
                catch (InvalidOperationException)
                {
                    CommandRunner.TryKill(farSide);
                }

                farSide.Dispose();
            }
        }
    }

    /// <summary>
    /// Hides the system D-Bus socket inside this mount namespace.
    /// </summary>
    /// <remarks>
    /// <c>resolvectl</c> talks to systemd-resolved over that socket, and the resolved instance
    /// answering it lives in the host's namespaces: a link name that exists here would be resolved
    /// to an interface index, and that index would then be applied to whatever the host happens to
    /// have at the same number. Hiding the socket makes the reachability probe fail — which is
    /// exactly what a machine without systemd-resolved does — and leaves the DNS executor on its
    /// documented file backend. The bind mount happens inside a private mount namespace, so the
    /// host's file is untouched.
    /// </remarks>
    private static bool HideSystemBus(RootlessReport report)
    {
        const string socketPath = "/run/dbus/system_bus_socket";

        if (!File.Exists(socketPath))
        {
            report.Trace.Add("system bus socket absent; nothing to hide");
            return false;
        }

        if (!File.Exists("/bin/mount"))
        {
            report.Trace.Add("mount is unavailable; the system bus socket could not be hidden");
            return false;
        }

        var hidden = RunQuietly("/bin/mount", new[] { "--bind", "/dev/null", socketPath });
        report.Trace.Add(hidden
            ? $"hid {socketPath} with a bind mount inside the private mount namespace"
            : $"could not hide {socketPath}");

        return hidden;
    }

    /// <summary>Whether <c>resolvectl</c> can reach a resolver — i.e. whether the host's is exposed.</summary>
    private static bool ResolvectlAnswers() =>
        File.Exists("/usr/bin/resolvectl") && RunQuietly("/usr/bin/resolvectl", new[] { "status" });

    private static bool RunQuietly(string fileName, IReadOnlyList<string> arguments)
    {
        try
        {
            var info = new ProcessStartInfo
            {
                FileName = fileName,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardError = true,
            };

            foreach (var argument in arguments)
            {
                info.ArgumentList.Add(argument);
            }

            using var process = Process.Start(info);
            if (process is null)
            {
                return false;
            }

            process.WaitForExit(5000);
            return process.ExitCode == 0;
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            return false;
        }
    }

    private static Process StartFarSide(HarnessArgs arguments, string work)
    {
        var dotnet = string.IsNullOrEmpty(arguments.Dotnet)
            ? Environment.ProcessPath ?? "dotnet"
            : arguments.Dotnet;

        var harness = string.IsNullOrEmpty(arguments.HarnessPath)
            ? Environment.GetCommandLineArgs()[0]
            : arguments.HarnessPath;

        var unshare = File.Exists("/usr/bin/unshare") ? "/usr/bin/unshare" : "unshare";

        var info = new ProcessStartInfo
        {
            FileName = unshare,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            WorkingDirectory = work,
        };

        info.ArgumentList.Add("-n");
        info.ArgumentList.Add(dotnet);
        info.ArgumentList.Add(harness);
        info.ArgumentList.Add(HarnessArgs.ServerRoleName);
        info.ArgumentList.Add("--work");
        info.ArgumentList.Add(work);
        info.ArgumentList.Add("--xray");
        info.ArgumentList.Add(arguments.Xray);
        info.ArgumentList.Add("--user-id");
        info.ArgumentList.Add(arguments.UserId);
        info.ArgumentList.Add("--server-port");
        info.ArgumentList.Add(arguments.ServerPort.ToString(CultureInfo.InvariantCulture));

        var process = Process.Start(info)
            ?? throw new InvalidOperationException("could not start the far-side namespace");

        var log = new StreamWriter(Path.Combine(work, "server-helper.log"), append: false) { AutoFlush = true };
        process.OutputDataReceived += (_, e) => { if (e.Data is not null) { log.WriteLine(e.Data); } };
        process.ErrorDataReceived += (_, e) => { if (e.Data is not null) { log.WriteLine(e.Data); } };
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();

        return process;
    }

    private static async Task IpAsync(RootlessReport report, params string[] arguments)
    {
        var result = await CommandRunner.RunAsync(CommandRunner.IpBinary, arguments, IpTimeout).ConfigureAwait(false);

        report.Trace.Add($"ip {string.Join(' ', arguments)} → {result}");

        if (!result.Succeeded)
        {
            throw new InvalidOperationException(
                $"namespace setup failed: {CommandRunner.Describe(CommandRunner.IpBinary, arguments)}: {result}");
        }
    }

    private static async Task WaitForAsync(Func<bool> condition, TimeSpan timeout, CancellationToken cancellationToken)
    {
        var deadline = DateTime.UtcNow + timeout;

        while (DateTime.UtcNow < deadline && !cancellationToken.IsCancellationRequested)
        {
            if (condition())
            {
                return;
            }

            await Task.Delay(TimeSpan.FromMilliseconds(100), cancellationToken).ConfigureAwait(false);
        }
    }

    private static string FailDetail(string errorPath, string coreLogPath, Process? farSide)
    {
        var detail = KernelState.ReadFileOrEmpty(errorPath);

        if (detail.Length == 0 && farSide is not null)
        {
            detail = $"far-side helper exited with {farSide.ExitCode}";
        }

        var log = TailOf(coreLogPath, 10);
        return log.Length == 0 ? detail : $"{detail} | core log: {OneLine(log)}";
    }

    private static string TailOf(string path, int lines)
    {
        var content = KernelState.ReadFileOrEmpty(path);
        if (content.Length == 0)
        {
            return string.Empty;
        }

        var all = content.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        return string.Join("\n", all.Skip(Math.Max(0, all.Length - lines)));
    }

    private static List<string> ReadLines(string path) =>
        KernelState.ReadFileOrEmpty(path)
            .Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Select(line => line.Trim())
            .ToList();

    private static void Trace(RootlessReport report, string message) => report.Trace.Add(message);

    private static string OneLine(string text) => text.ReplaceLineEndings(" | ").Trim();

    private static string NftSummary(string table) => table.Length == 0
        ? "(absent)"
        : string.Create(
            CultureInfo.InvariantCulture,
            $"({table.Split('\n').Length} lines, marker present: {table.Contains("myvpn: default deny", StringComparison.Ordinal)})");
}
