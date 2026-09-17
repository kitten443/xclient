using System.Globalization;
using Microsoft.Extensions.Logging;
using MyVpn.Application.Abstractions;
using MyVpn.Application.Connection;
using MyVpn.Core.Domain;
using MyVpn.Core.Parsing;
using MyVpn.Core.Settings;
using MyVpn.Core.Subscriptions;
using MyVpn.Infrastructure.App;
using MyVpn.Infrastructure.Geo;
using MyVpn.Infrastructure.Net;
using MyVpn.Infrastructure.Subscriptions;
using MyVpn.Infrastructure.Xray;
using MyVpn.Platform.Linux.KillSwitch;
using MyVpn.Platform.Linux.Dns;
using MyVpn.Platform.Linux.Proxy;
using MyVpn.Platform.Linux.Routing;

namespace MyVpn.Cli;

/// <summary>
/// <c>myvpn connect</c> — establishes a tunnel from a subscription and reports what happened.
/// </summary>
/// <remarks>
/// This exists so the whole connect path can be exercised without the GUI. It uses exactly the
/// same application services the UI will, which is what keeps the UI thin and this path honest.
/// </remarks>
internal static class ConnectCommand
{
    public static async Task<int> RunAsync(string[] args, ILoggerFactory loggerFactory)
    {
        var subscriptionUrl = ReadOption(args, "--subscription");
        var profileIndex = int.TryParse(
            ReadOption(args, "--index") ?? "0",
            NumberStyles.Integer,
            CultureInfo.InvariantCulture,
            out var parsedIndex) ? parsedIndex : 0;

        var mode = (ReadOption(args, "--mode") ?? "proxy").ToLowerInvariant() switch
        {
            "tun" => TunnelMode.Tun,
            "off" or "disabled" => TunnelMode.Disabled,
            _ => TunnelMode.SystemProxy,
        };

        var holdSeconds = int.TryParse(
            ReadOption(args, "--hold") ?? "0",
            NumberStyles.Integer,
            CultureInfo.InvariantCulture,
            out var parsedHold) ? parsedHold : 0;

        var paths = new AppPaths();
        paths.EnsureCreated();

        var killSwitchMode = (ReadOption(args, "--kill-switch") ?? "off").ToLowerInvariant() switch
        {
            "on-demand" or "ondemand" => KillSwitchMode.OnDemand,
            "always-on" or "alwayson" => KillSwitchMode.AlwaysOn,
            _ => KillSwitchMode.Disabled,
        };

        var settings = new AppSettings
        {
            TunnelMode = mode,
            KillSwitch = killSwitchMode,

            // Plain HTTP for a subscription is allowed only when explicitly requested. It is a
            // real use case -- a self-hosted panel on a LAN -- but it is also how a subscription
            // URL and the credentials it carries end up readable in transit, so it is never a
            // default and never silent.
            Subscriptions = new SubscriptionSettings
            {
                AllowInsecureHttp = args.Contains("--allow-http", StringComparer.OrdinalIgnoreCase),
                AllowPrivateAddresses = args.Contains("--allow-private-subscription", StringComparer.OrdinalIgnoreCase),
            },
            Dns = new DnsSettings { Mode = DnsMode.ThroughTunnel },
            Routing = new RoutingSettings { BypassLan = true },
            Proxy = new ProxySettings { ListenPort = 10808, EnableSocks = true, EnableHttp = true },
            Logging = new LoggingSettings { Verbosity = LogVerbosity.Warning },
        };

        ServerProfile? profile = null;

        // ---- obtain a profile -------------------------------------------------
        if (!string.IsNullOrWhiteSpace(subscriptionUrl))
        {
            Console.WriteLine("Fetching the subscription…");

            using var fetcher = new SubscriptionFetcher();
            var fetched = await fetcher.FetchAsync(subscriptionUrl, settings.Subscriptions, CancellationToken.None);

            if (fetched.IsFailure)
            {
                Console.Error.WriteLine($"fetch failed: {fetched.Error}");
                return 70;
            }

            var registry = SubscriptionHeaderRegistry.CreateDefault();
            var bag = registry.CreateBag(fetched.Value.Headers);
            var parsed = registry.Parse(new HeaderParseContext
            {
                Headers = bag,
                SubscriptionId = "cli",
                SubscriptionUrl = new Uri(fetched.Value.FinalUrl),
            });

            var batch = ShareLinkParser.ParseMany(fetched.Value.Body);

            Console.WriteLine($"  title        : {parsed.Metadata.Title ?? "(none)"}");
            Console.WriteLine($"  profiles     : {batch.Profiles.Count} (parse failures: {batch.Failures.Count})");

            if (parsed.RefusedHeaders.Count > 0)
            {
                // Surfaced, never applied: a provider-supplied routing config is exactly the
                // arbitrary-config-injection case the gates refuse.
                Console.WriteLine($"  refused      : {string.Join(", ", parsed.RefusedHeaders)} (not applied)");
            }

            if (parsed.PendingChanges.Count > 0)
            {
                Console.WriteLine($"  needs consent: {string.Join(", ", parsed.PendingChanges.Select(c => c.HeaderName))}");
            }

            if (batch.Profiles.Count == 0)
            {
                Console.Error.WriteLine("The subscription contained no usable profiles.");
                return 71;
            }

            if (profileIndex < 0 || profileIndex >= batch.Profiles.Count)
            {
                Console.Error.WriteLine($"--index {profileIndex} is out of range (0..{batch.Profiles.Count - 1}).");
                return 64;
            }

            profile = batch.Profiles[profileIndex];
            Console.WriteLine($"  selected     : [{profileIndex}] {profile.DisplayName} ({profile.Protocol} {profile.Transport}/{profile.Security})");
        }
        else
        {
            Console.Error.WriteLine("--subscription <url> is required.");
            return 64;
        }

        Console.WriteLine();

        // ---- compose the session ---------------------------------------------
        var stateMachine = new VpnStateMachine();
        var geoManager = new GeoDataManager(
            new GeoDataOptions
            {
                AssetDirectory = paths.GeoDataDirectory,
                SeedDirectory = paths.SeedGeoDataDirectory,
                BackupDirectory = paths.GeoBackupDirectory,
                ManifestPath = paths.GeoManifestPath,
            },
            loggerFactory.CreateLogger<GeoDataManager>());

        var engine = new XrayEngineManager(
            loggerFactory.CreateLogger<XrayEngineManager>(),
            new XrayEngineOptions { AutoRestart = false });

        var session = new VpnSession(
            stateMachine,
            paths,
            new AtomicConfigFileStore(),
            new CoreLocatorAdapter(engine),
            new CoreSupervisorAdapter(engine),
            new GeoDataProviderAdapter(geoManager),
            new DnsServerEndpointResolver(),
            new HttpProxyConnectionVerifier(),

            // Both executors are real. The Kill Switch reports "not available" when the process is
            // not elevated, which is the honest answer rather than a false claim of protection; the
            // system proxy applies only with --system-proxy, because pointing a desktop at a tunnel
            // is a side effect that should never happen as a surprise.
            killSwitch: new NftablesKillSwitch(),
            systemProxy: args.Contains("--system-proxy", StringComparer.OrdinalIgnoreCase)
                ? new LinuxSystemProxy()
                : null,

            // Routes and DNS are only consulted in TUN mode; in system-proxy mode the core
            // hijacks port 53 itself, so the operating system's resolver is left alone.
            routes: new LinuxRouteManager(),
            dns: new LinuxDnsConfigurator(),
            loggerFactory.CreateLogger<VpnSession>());

        session.SnapshotChanged += (_, snapshot) =>
            Console.WriteLine($"  [state] {snapshot.State}");

        Console.WriteLine($"Connecting (mode={mode})…");
        Console.WriteLine();

        var connected = await session.ConnectAsync(
            new ConnectRequest
            {
                Profile = profile,
                Settings = settings,
                CoreBinaryPath = ReadOption(args, "--core"),
            },
            CancellationToken.None);

        if (connected.IsFailure)
        {
            Console.Error.WriteLine($"CONNECT FAILED: {connected.Error!.Code} — {connected.Error.MessageKey}");
            Console.Error.WriteLine($"  detail: {connected.Error.TechnicalDetail}");

            foreach (var line in engine.GetRecentOutput(8))
            {
                Console.Error.WriteLine($"  core: {line}");
            }

            return 6;
        }

        var result = connected.Value;

        Console.WriteLine();
        Console.WriteLine("CONNECTED");
        Console.WriteLine($"  profile      : {result.ProfileName}");
        Console.WriteLine($"  core         : {result.CoreVersion ?? "unknown"} (pid {result.CoreProcessId})");
        Console.WriteLine($"  config       : {result.ConfigPath}");

        if (result.Verification is { } verification)
        {
            Console.WriteLine($"  exit address : {verification.ExitAddress}  ({verification.Method})");
            Console.WriteLine($"  direct        : {verification.DirectAddress ?? "unknown"}");
            Console.WriteLine($"  moved traffic : {(verification.ExitDiffersFromDirect ? "YES" : "NO — traffic may not be tunnelled")}");
            Console.WriteLine($"  latency      : {verification.Latency.TotalMilliseconds:0} ms");
        }
        else
        {
            Console.WriteLine("  exit address : (verification skipped)");
        }

        if (result.Warnings.Count > 0)
        {
            Console.WriteLine();
            Console.WriteLine("Warnings:");
            foreach (var warning in result.Warnings)
            {
                Console.WriteLine($"  [{warning.Severity}] {warning.MessageKey} — {warning.TechnicalDetail}");
            }
        }

        if (holdSeconds > 0)
        {
            Console.WriteLine();
            Console.WriteLine($"Holding for {holdSeconds}s…");
            await Task.Delay(TimeSpan.FromSeconds(holdSeconds), CancellationToken.None);
        }

        Console.WriteLine();
        Console.WriteLine("Disconnecting…");
        var disconnected = await session.DisconnectAsync(CancellationToken.None);

        Console.WriteLine(disconnected.IsSuccess
            ? "DISCONNECTED (network state restored)"
            : $"disconnect reported a problem: {disconnected.Error}");

        return 0;
    }

    private static string? ReadOption(string[] args, string name)
    {
        for (var i = 0; i < args.Length - 1; i++)
        {
            if (args[i].Equals(name, StringComparison.OrdinalIgnoreCase))
            {
                return args[i + 1];
            }
        }

        return null;
    }
}
