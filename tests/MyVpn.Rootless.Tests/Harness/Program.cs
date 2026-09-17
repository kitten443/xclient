using System.Text.Json;

namespace MyVpn.Rootless.Harness;

/// <summary>
/// The program that runs <i>inside</i> the throwaway namespaces.
/// </summary>
/// <remarks>
/// <para>
/// It is started twice per scenario. The outer process is the client: it owns the namespace the
/// test created with <c>unshare -rmn --propagation private</c>, builds the uplink, starts the far
/// side and drives the real <c>VpnSession</c>. The inner process is the far side: it is started by
/// the client with a plain <c>unshare -n</c>, and hosts the core's server plus the traffic target.
/// </para>
/// <para>
/// It exits non-zero only when the <i>rig</i> failed. Whether the tunnel behaved is not this
/// process's opinion to hold: it writes what it observed to a JSON report and the xUnit test
/// decides. That split keeps a broken assertion from hiding behind an exit code, and it keeps a
/// genuine product failure from looking like a broken test.
/// </para>
/// </remarks>
internal static class HarnessProgram
{
    public static async Task<int> Main(string[] args)
    {
        EnsureUsablePath();

        if (!HarnessArgs.TryParse(args, out var arguments, out var error))
        {
            await Console.Error.WriteLineAsync($"harness: {error}").ConfigureAwait(false);
            return 64;
        }

        using var cancellation = new CancellationTokenSource(TimeSpan.FromMinutes(5));

        try
        {
            if (arguments.Role == HarnessArgs.ServerRoleName)
            {
                return await ServerRole.RunAsync(arguments, cancellation.Token).ConfigureAwait(false);
            }

            var report = await ClientScenario.RunAsync(arguments, cancellation.Token).ConfigureAwait(false);
            var reportPath = Path.Combine(arguments.Work, "report.json");

            await File.WriteAllTextAsync(
                reportPath,
                JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }),
                CancellationToken.None).ConfigureAwait(false);

            foreach (var line in report.Trace)
            {
                await Console.Out.WriteLineAsync(line).ConfigureAwait(false);
            }

            if (report.Failure is not null)
            {
                await Console.Error.WriteLineAsync($"harness: {report.Failure}").ConfigureAwait(false);
                return 1;
            }

            return report.Client.ConnectSucceeded && report.Completed ? 0 : 1;
        }
        catch (Exception ex)
        {
            await Console.Error.WriteLineAsync($"harness: {ex}").ConfigureAwait(false);
            return 70;
        }
    }

    /// <summary>
    /// Guarantees the tools the platform layer looks up by name are reachable.
    /// </summary>
    /// <remarks>
    /// <c>ip</c> and <c>nft</c> live in <c>/usr/sbin</c> on most distributions, and a process
    /// started from a test runner can inherit a minimal <c>PATH</c>. <c>LinuxRouteManager</c>
    /// already prefers the absolute <c>/usr/sbin/ip</c>, and this makes the rest — the kill
    /// switch's <c>nft</c>, the TUN observer's <c>ip</c> — behave the same way rather than
    /// reporting "tool missing" and quietly skipping work.
    /// </remarks>
    private static void EnsureUsablePath()
    {
        var current = Environment.GetEnvironmentVariable("PATH") ?? string.Empty;
        var required = new[] { "/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin" };
        var missing = required
            .Where(directory => !current.Split(':', StringSplitOptions.RemoveEmptyEntries).Contains(directory, StringComparer.Ordinal))
            .ToArray();

        if (missing.Length > 0)
        {
            Environment.SetEnvironmentVariable(
                "PATH",
                string.Join(':', missing) + (current.Length == 0 ? string.Empty : ":" + current));
        }

        // The harness must not depend on telemetry or a first-run experience to be quiet.
        Environment.SetEnvironmentVariable("DOTNET_CLI_TELEMETRY_OPTOUT", "1");
        Environment.SetEnvironmentVariable("DOTNET_NOLOGO", "1");
        Environment.SetEnvironmentVariable(
            "DOTNET_ROOT",
            Environment.GetEnvironmentVariable("DOTNET_ROOT")
            ?? Path.GetDirectoryName(Environment.ProcessPath) ?? string.Empty);
    }
}
