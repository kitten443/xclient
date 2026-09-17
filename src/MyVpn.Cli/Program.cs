using System.Globalization;
using Microsoft.Extensions.Logging;
using MyVpn.Core.Diagnostics;
using MyVpn.Core.Geo;
using MyVpn.Core.Results;
using MyVpn.Core.Settings;
using MyVpn.Infrastructure.Diagnostics;
using MyVpn.Infrastructure.Geo;

namespace MyVpn.Cli;

/// <summary>
/// Headless entry point.
/// </summary>
/// <remarks>
/// Exists for three reasons: it lets the real pipeline be exercised on a CI runner with no
/// GUI, it gives users a way to collect diagnostics from a terminal, and it keeps the GUI
/// honest — anything the GUI can do must be reachable through the same application services.
/// </remarks>
internal static class Program
{
    private static int Main(string[] args)
    {
        Console.OutputEncoding = System.Text.Encoding.UTF8;

        if (args.Length == 0 || IsHelp(args[0]))
        {
            PrintUsage();
            return 0;
        }

        using var loggerFactory = LoggerFactory.Create(builder => builder
            .AddSimpleConsole(options => options.SingleLine = true)
            .SetMinimumLevel(LogLevel.Information));

        try
        {
            return args[0].ToLowerInvariant() switch
            {
                "version" or "--version" or "-v" => PrintVersion(),
                "geo" => RunGeo(args, loggerFactory),
                "diagnose" => RunDiagnose(args, loggerFactory),
                "connect" => ConnectCommand.RunAsync(args, loggerFactory).GetAwaiter().GetResult(),
                _ => Unknown(args[0]),
            };
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"unexpected failure: {ex.Message}");
            return 70;
        }
    }

    private static bool IsHelp(string arg) =>
        arg is "--help" or "-h" or "help";

    private static void PrintUsage()
    {
        Console.WriteLine("myvpn — Xray VPN client (headless driver)");
        Console.WriteLine();
        Console.WriteLine("Usage:");
        Console.WriteLine("  myvpn version                 Show the client version.");
        Console.WriteLine("  myvpn geo doctor [--dir P]    Inspect geo data and report problems.");
        Console.WriteLine("  myvpn diagnose [options]      Run the built-in connection diagnostics.");
        Console.WriteLine("      --dir P       Geo data directory (absolute).");
        Console.WriteLine("      --core P      Path to the Xray core binary.");
        Console.WriteLine("      --config P    Path to a generated configuration file.");
        Console.WriteLine("      --online      Also run checks that need the network.");
        Console.WriteLine("  myvpn connect [options]       Connect through a subscription.");
        Console.WriteLine("      --subscription URL   Subscription URL (required).");
        Console.WriteLine("      --index N            Which profile to use (default 0).");
        Console.WriteLine("      --mode proxy|tun     Tunnel mode (default proxy).");
        Console.WriteLine("      --hold SECONDS       Stay connected before disconnecting.");
        Console.WriteLine("      --core PATH          Path to the Xray core binary.");
        Console.WriteLine("  myvpn help                    Show this help.");
        Console.WriteLine();
        Console.WriteLine("Geo data must be reachable through an ABSOLUTE path; see ADR-0003.");
    }

    private static int PrintVersion()
    {
        var version = typeof(Program).Assembly.GetName().Version?.ToString() ?? "0.0.0";
        Console.WriteLine(Format("myvpn {0}", version));
        Console.WriteLine(Format("runtime {0}", Environment.Version));
        Console.WriteLine(Format("os {0}", Environment.OSVersion.VersionString));
        return 0;
    }

    /// <summary>
    /// Implements <c>myvpn geo doctor</c>: the diagnostic mode required for geo data.
    /// </summary>
    /// <remarks>
    /// Prints the resolved absolute asset directory, per-asset health with entry counts,
    /// any recorded problems in plain language, and the environment variable that will be
    /// handed to the core. This is the tool a user runs when the client says it cannot find
    /// <c>geoip.dat</c>.
    /// </remarks>
    private static int RunGeo(string[] args, ILoggerFactory loggerFactory)
    {
        var subcommand = args.Length > 1 ? args[1].ToLowerInvariant() : "doctor";
        if (subcommand != "doctor")
        {
            Console.Error.WriteLine(Format("unknown geo subcommand '{0}'", subcommand));
            return 64;
        }

        var assetDirectory = ReadOption(args, "--dir") ?? DefaultAssetDirectory();

        var manager = new GeoDataManager(
            new GeoDataOptions
            {
                AssetDirectory = assetDirectory,
                SeedDirectory = Environment.GetEnvironmentVariable("MYVPN_GEO_SEED"),
                BackupDirectory = Path.Combine(StateRoot(), "geodata-backup"),
                ManifestPath = Path.Combine(StateRoot(), "geodata-manifest.json"),
            },
            loggerFactory.CreateLogger<GeoDataManager>());

        var status = manager.InspectAsync(CancellationToken.None).GetAwaiter().GetResult();

        Console.WriteLine("Geo data diagnostics");
        Console.WriteLine("====================");
        Console.WriteLine(Format("asset directory : {0}", status.AssetDirectory));
        Console.WriteLine(Format("absolute        : {0}", status.IsAssetDirectoryAbsolute ? "yes" : "NO — this is a defect"));
        Console.WriteLine(Format("writable        : {0}", status.IsAssetDirectoryWritable ? "yes" : "no"));
        Console.WriteLine(Format("source          : {0}", status.ResolvedFrom ?? "unknown"));
        Console.WriteLine(Format("backup present  : {0}", status.HasBackupGeneration ? "yes" : "no"));
        Console.WriteLine();

        foreach (var asset in status.Assets)
        {
            Console.WriteLine(Format("{0} ({1})", asset.Kind.FileName(), asset.Kind.DisplayNameKey()));
            Console.WriteLine(Format("  health        : {0}", asset.Health));
            Console.WriteLine(Format("  path          : {0}", asset.AbsolutePath));
            Console.WriteLine(Format("  size          : {0} bytes", asset.SizeBytes.ToString("N0", CultureInfo.InvariantCulture)));
            Console.WriteLine(Format("  sha256        : {0}", asset.Sha256 ?? "(not computed)"));
            Console.WriteLine(Format("  entries       : {0}", asset.EntryCount.ToString(CultureInfo.InvariantCulture)));

            if (asset.SampleCodes.Count > 0)
            {
                Console.WriteLine(Format("  sample codes  : {0}", string.Join(", ", asset.SampleCodes)));
            }

            if (asset.FailureDetail is not null)
            {
                Console.WriteLine(Format("  problem       : {0}", asset.FailureDetail));
            }

            Console.WriteLine();
        }

        var environment = manager.BuildXrayEnvironment();
        Console.WriteLine("Environment handed to Xray:");
        foreach (var pair in environment)
        {
            Console.WriteLine(Format("  {0}={1}", pair.Key, pair.Value));
        }

        Console.WriteLine();
        Console.WriteLine(Format("usable: geoip={0} geosite={1}", status.GeoIp.IsUsable, status.GeoSite.IsUsable));

        if (status.AllUsable)
        {
            Console.WriteLine("RESULT: OK");
            return 0;
        }

        // Exit code 3 means "geo data is not usable", which is what the issue #9765 reports
        // were really about. Callers (and CI) can assert on it.
        Console.WriteLine("RESULT: geo data is NOT usable");
        var error = status.ToWorstError();
        if (error is not null)
        {
            Console.WriteLine(Format("reason: {0} — {1}", error.Code, error.MessageKey));
            Console.WriteLine(Format("repair: {0}", error.RemediationKey ?? "geodata.repair"));
        }

        return 3;
    }

    private static int RunDiagnose(string[] args, ILoggerFactory loggerFactory)
    {
        var stateRoot = StateRoot();
        var assetDirectory = ReadOption(args, "--dir") ?? Path.Combine(stateRoot, GeoDataConstants.DefaultAssetDirectoryName);

        var geoData = new GeoDataManager(
            new GeoDataOptions
            {
                AssetDirectory = assetDirectory,
                SeedDirectory = Environment.GetEnvironmentVariable("MYVPN_GEO_SEED"),
                BackupDirectory = Path.Combine(stateRoot, "geodata-backup"),
                ManifestPath = Path.Combine(stateRoot, "geodata-manifest.json"),
            },
            loggerFactory.CreateLogger<GeoDataManager>());

        var settings = new AppSettings();

        var context = new DiagnosticContext
        {
            Settings = settings,
            GeoData = geoData,
            CoreBinaryPath = ReadOption(args, "--core"),
            ConfigPath = ReadOption(args, "--config"),
            AssetDirectory = assetDirectory,
            WorkingDirectory = stateRoot,

            // Offline mode: the CLI does not attempt a server connection unless asked, so the
            // command is safe to run on a machine with no working network.
            AllowNetworkChecks = args.Contains("--online", StringComparer.OrdinalIgnoreCase),
        };

        var runner = new DiagnosticRunner(
            DiagnosticRunner.CreateDefaultChecks(),
            loggerFactory.CreateLogger<DiagnosticRunner>());

        var report = runner.RunAsync(context, CancellationToken.None).GetAwaiter().GetResult();

        Console.WriteLine(report.ToPlainTextSummary());
        Console.WriteLine();
        Console.WriteLine(Format("overall: {0}", report.Overall));

        // Exit codes: 0 healthy, 4 warnings only, 5 errors present. Callers and CI can assert on
        // these without parsing text.
        return report.Overall switch
        {
            DiagnosticStatus.Success => 0,
            DiagnosticStatus.Skipped => 0,
            DiagnosticStatus.Warning => 4,
            _ => 5,
        };
    }

    private static int Unknown(string arg)
    {
        Console.Error.WriteLine(Format("unknown command '{0}'", arg));
        PrintUsage();
        return 64;
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

    private static string StateRoot()
    {
        var platform = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        return Path.Combine(
            string.IsNullOrEmpty(platform) ? Path.GetTempPath() : platform,
            "MyVpn");
    }

    private static string DefaultAssetDirectory() => Path.Combine(StateRoot(), GeoDataConstants.DefaultAssetDirectoryName);

    private static string Format(string template, params object?[] arguments) =>
        string.Format(CultureInfo.InvariantCulture, template, arguments);
}
